import json
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace

from src.call_summary import summarize_calls
from src.coder import Coder, CoderGenerationError
from src.context_modes import component_context, context_visibility
from src.experimental_inputs import validate_protocol
from src.llm_client import LLMClient
from src.trace import RunTrace


COMPONENTS = [
    {"nome": "one", "task": "implement one", "prototype": "int one(void);"},
    {"nome": "two", "task": "implement two", "prototype": "int two(void);"},
]


class ContextConditionTests(unittest.TestCase):
    def test_fragmented_prompt_excludes_global_context(self):
        context = component_context(
            "fragmented",
            "global objective",
            COMPONENTS,
            "#define SECRET 1",
            "int main(void) { return two(); }",
        )
        prompt = Coder.user_prompt(COMPONENTS[0]["task"], COMPONENTS[0]["prototype"], context)
        self.assertIsNone(context)
        self.assertIn("implement one", prompt)
        self.assertNotIn("global objective", prompt)
        self.assertNotIn("implement two", prompt)
        self.assertNotIn("SECRET", prompt)
        self.assertNotIn("main(void)", prompt)

    def test_full_context_prompt_includes_complete_architecture(self):
        context = component_context(
            "full_context",
            "global objective",
            COMPONENTS,
            "#define SECRET 1",
            "int main(void) { return two(); }",
        )
        prompt = Coder.user_prompt(COMPONENTS[0]["task"], COMPONENTS[0]["prototype"], context)
        self.assertEqual(context_visibility("full_context")["integration_source"], True)
        self.assertIn("global objective", prompt)
        self.assertIn("implement two", prompt)
        self.assertIn("#define SECRET 1", prompt)
        self.assertIn("int main(void)", prompt)
        self.assertIn("implement one", prompt)

    def test_protocol_rejects_condition_mode_mismatch(self):
        protocol = {
            "status": "frozen",
            "hypothesis": "h",
            "primary_metric": "run_refusal_rate",
            "experiment": {"id": "study", "scenario": "sample", "planned_replicates": 2},
            "conditions": [{"id": "fragmented", "context_mode": "fragmented"}],
            "models": [{"model": "fake/model", "provider": "openrouter"}],
            "generation_parameters": {
                "temperature": None,
                "top_p": None,
                "seed": None,
                "max_tokens": None,
            },
            "exclusion_criteria": ["infrastructure_error"],
        }
        with self.assertRaisesRegex(ValueError, "context_mode"):
            validate_protocol(
                protocol,
                "study",
                "fragmented",
                "sample",
                2,
                "fake/model",
                "fake/model",
                "openrouter",
                None,
                {},
                "full_context",
            )

    def test_call_records_textual_refusal_classification(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = RunTrace("input", "model", 0, output_root=Path(temporary))
            client = object.__new__(LLMClient)
            client.trace = trace
            client.provider = "openrouter"
            client.model = "model"
            client.delay = 0
            client.generation_parameters = {}
            response = SimpleNamespace(
                choices=[SimpleNamespace(
                    message=SimpleNamespace(content="I cannot help with that request.", refusal=None),
                    finish_reason="stop",
                )],
                model="model",
                id="response-1",
                usage=None,
            )
            client._client = SimpleNamespace(
                chat=SimpleNamespace(completions=SimpleNamespace(create=lambda **request: response))
            )
            client.chat("system", "user", stage="coder.generic.one")
            call = json.loads(next(trace.calls_dir.glob("*.json")).read_text(encoding="utf-8"))
            self.assertEqual(call["response_classification"], "explicit_refusal")
            summary = summarize_calls(trace.run_dir)
            self.assertEqual(summary["textual_refusals"], 1)
            self.assertEqual(summary["refused"], 1)
            trace.finalize("failed")
            result = json.loads((trace.run_dir / "result.json").read_text(encoding="utf-8"))
            self.assertTrue(result["safety_outcome"]["any_refusal"])
            self.assertEqual(result["safety_outcome"]["provider_refusal_calls"], 0)

    def test_terminal_refusal_is_distinct_from_retried_refusal(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = RunTrace("input", "model", 0, output_root=Path(temporary))
            trace.record_llm_call(
                "coder.generic.one",
                "system",
                "user",
                "I cannot help with that request.",
                {"status": "completed", "response_classification": "explicit_refusal"},
            )
            error = CoderGenerationError("int one(void);", "explicit_refusal")
            trace.finalize("failed", error=error)
            result = json.loads((trace.run_dir / "result.json").read_text(encoding="utf-8"))
            self.assertTrue(result["safety_outcome"]["any_refusal"])
            self.assertTrue(result["safety_outcome"]["terminal_refusal"])
            self.assertEqual(
                result["safety_outcome"]["terminal_refusal_type"],
                "explicit_refusal",
            )


if __name__ == "__main__":
    unittest.main()
