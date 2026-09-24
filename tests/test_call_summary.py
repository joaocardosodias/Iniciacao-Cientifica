import json
import socket
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src.llm_client import LLMClient, ModelRefusalError
from src.recovery import recover_run
from src.trace import RunTrace


class CallSummaryTests(unittest.TestCase):
    def test_aggregates_outcomes_usage_retries_cost_and_observed_models(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = RunTrace("entrada", "modelo solicitado", 0, output_root=Path(temporary))
            trace.record_llm_call("primeira", "sistema", "usuario", "ok", {
                "status": "completed", "provider": "openrouter",
                "requested_model": "modelo solicitado", "response_model": "modelo observado",
                "inference_provider": "provedor observado",
                "attempts": [
                    {"status": "retryable_error"},
                    {"status": "retryable_error"},
                    {"status": "completed"},
                ],
                "usage": {"prompt_tokens": 10, "completion_tokens": 4,
                          "total_tokens": 14, "cost": 0.1},
            })
            trace.record_llm_call("segunda", "sistema", "usuario", "", {
                "status": "empty_response", "provider": "groq",
                "response_model": "outro modelo", "attempts": [{"status": "completed"}],
                "usage": {"prompt_tokens": 2, "completion_tokens": 0, "cost": 0.2},
            })
            trace.record_llm_call("terceira", "sistema", "usuario", None, {
                "status": "api_error", "provider": "openrouter",
                "requested_model": "modelo solicitado", "attempts": [{"status": "error"}],
                "usage": None,
            })
            trace.finalize("failed", error=RuntimeError("falha"))
            result = json.loads((trace.run_dir / "result.json").read_text())
            calls = result["llm_calls"]
            self.assertEqual(calls["total"], 3)
            self.assertEqual(calls["completed"], 1)
            self.assertEqual(calls["errors"], 1)
            self.assertEqual(calls["empty_responses"], 1)
            self.assertEqual(calls["retries"], 2)
            self.assertEqual(calls["tokens"], {
                "input": 12, "output": 4, "total": 16, "reported_calls": 2,
            })
            self.assertEqual(calls["cost"], {
                "total": 0.3, "reported_calls": 2, "unit": "provider_reported",
            })
            self.assertEqual(calls["models_observed"], ["modelo observado", "outro modelo"])
            self.assertEqual(calls["providers_observed"], ["groq", "openrouter"])
            self.assertEqual(calls["inference_providers_observed"], ["provedor observado"])
            self.assertNotIn("sistema", json.dumps(calls))
            self.assertNotIn("usuario", json.dumps(calls))

    def test_empty_run_and_unavailable_cost(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = RunTrace("entrada", "modelo", 0, output_root=Path(temporary))
            trace.finalize("completed")
            calls = json.loads((trace.run_dir / "result.json").read_text())["llm_calls"]
            self.assertEqual(calls["total"], 0)
            self.assertIsNone(calls["cost"]["total"])
            self.assertEqual(calls["cost"]["unit"], "provider_reported")
            self.assertEqual(calls["tokens"]["reported_calls"], 0)

    def test_recovered_run_preserves_partial_call_summary(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = RunTrace("entrada", "modelo", 0, output_root=Path(temporary))
            trace.record_llm_call("etapa", "sistema", "usuario", "ok", {
                "status": "completed", "provider": "groq", "response_model": "modelo-a",
                "usage": {"prompt_tokens": 3, "completion_tokens": 5, "total_tokens": 8},
                "attempts": [{"status": "completed"}],
            })
            trace.manifest["process"] = {"pid": 999999999, "hostname": socket.gethostname()}
            trace._save_manifest()
            with patch("src.recovery.process_alive", return_value=False):
                outcome = recover_run(trace.run_dir)
            self.assertEqual(outcome["terminal_status"], "abandoned")
            result = json.loads((trace.run_dir / "result.json").read_text())
            self.assertEqual(result["llm_calls"]["total"], 1)
            self.assertEqual(result["llm_calls"]["tokens"]["total"], 8)

    def test_client_persists_provider_and_cost_from_api_response(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = RunTrace("entrada", "modelo", 0, output_root=Path(temporary))
            client = object.__new__(LLMClient)
            client.trace = trace
            client.provider = "openrouter"
            client.model = "modelo"
            client.delay = 0
            client.generation_parameters = {}
            usage = SimpleNamespace(
                prompt_tokens=2, completion_tokens=3, total_tokens=5,
                model_extra={"cost": 0.125},
            )
            response = SimpleNamespace(
                usage=usage, model="modelo-real", id="response-1",
                model_extra={"provider": "provedor-via-extra"},
                choices=[SimpleNamespace(message=SimpleNamespace(content="resposta"))],
            )
            direct_response = SimpleNamespace(
                usage=None, model="modelo-real", id="response-2",
                provider="provedor-direto", model_extra={"provider": "ignorado"},
                choices=[SimpleNamespace(message=SimpleNamespace(content="resposta"))],
            )
            unavailable_response = SimpleNamespace(
                usage=None, model="modelo-real", id="response-3",
                choices=[SimpleNamespace(message=SimpleNamespace(content="resposta"))],
            )
            responses = iter([response, direct_response, unavailable_response])
            client._client = SimpleNamespace(chat=SimpleNamespace(
                completions=SimpleNamespace(create=lambda **request: next(responses))
            ))
            for _ in range(3):
                self.assertEqual(client.chat("sistema", "usuario", stage="etapa"), "resposta")
            trace.finalize("completed")
            result = json.loads((trace.run_dir / "result.json").read_text())
            self.assertEqual(result["llm_calls"]["cost"]["total"], 0.125)
            self.assertEqual(result["llm_calls"]["models_observed"], ["modelo-real"])
            self.assertEqual(result["llm_calls"]["inference_providers_observed"], [
                "provedor-direto", "provedor-via-extra",
            ])
            calls = sorted(trace.calls_dir.glob("*.json"))
            self.assertEqual([
                json.loads(path.read_text())["inference_provider"] for path in calls
            ], ["provedor-via-extra", "provedor-direto", None])
            events = [json.loads(line) for line in (trace.run_dir / "events.jsonl").read_text().splitlines()]
            finished = [event["data"]["inference_provider"] for event in events
                        if event["event"] == "llm.call.finished"]
            self.assertEqual(finished, ["provedor-via-extra", "provedor-direto", None])

    def test_chat_raises_on_provider_content_filter(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = RunTrace("entrada", "modelo", 0, output_root=Path(temporary))
            client = object.__new__(LLMClient)
            client.trace = trace
            client.provider = "openrouter"
            client.model = "anthropic/claude-opus-5.5"
            client.delay = 0
            client.generation_parameters = {}
            message = SimpleNamespace(content=None, refusal="blocked by policy")
            response = SimpleNamespace(
                choices=[SimpleNamespace(message=message, finish_reason="content_filter")],
                model="anthropic/claude-opus-5.5",
                id="resp-1",
                usage=None,
            )
            client._client = SimpleNamespace(chat=SimpleNamespace(
                completions=SimpleNamespace(create=lambda **request: response)))
            with self.assertRaises(ModelRefusalError):
                client.chat("sistema", "usuario", stage="coder.generic.f")
            call = json.loads(next((trace.run_dir / "calls").glob("*.json")).read_text())
            self.assertEqual(call["status"], "refused")
            self.assertEqual(call["finish_reason"], "content_filter")
            self.assertEqual(call["refusal"], "blocked by policy")

    def test_zero_cost_is_reported(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = RunTrace("entrada", "modelo", 0, output_root=Path(temporary))
            trace.record_llm_call("etapa", "sistema", "usuario", "ok", {
                "status": "completed", "usage": {"cost": 0},
            })
            trace.finalize("completed")
            cost = json.loads((trace.run_dir / "result.json").read_text())["llm_calls"]["cost"]
            self.assertEqual(cost, {"total": 0.0, "reported_calls": 1,
                                    "unit": "provider_reported"})


if __name__ == "__main__":
    unittest.main()
