import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pipeline
from src.trace import RunTrace, sha256_text


class FakeLLMClient:
    def __init__(self, model=None, **kwargs):
        self.model = model or "fake/model"
        self.provider = "fake"


class FakeSanitizer:
    def __init__(self, llm):
        self.llm = llm

    def sanitize(self, prompt):
        return "requisitos sanitizados"


class FakePlanner:
    def __init__(self, llm):
        self.llm = llm

    def plan(self, prompt):
        return [
            {"nome": "module_one", "descricao": "primeiro modulo"},
            {"nome": "module_two", "descricao": "segundo modulo"},
        ]


class FailingPlanner:
    def __init__(self, llm):
        self.llm = llm

    def plan(self, prompt):
        raise ValueError("invalid planner response")


class FakePromptMaker:
    def __init__(self, llm, seed=None):
        self.llm = llm

    def make(self, module, stage_prefix=None):
        return f"prompt para {module['nome']}"


class FakeCoder:
    def __init__(self, llm):
        self.llm = llm

    def generate(self, prompt, stage="coder"):
        return f"int {stage.replace('.', '_')}(void) {{ return 0; }}"


class FakeAssemblerHarness:
    def __init__(self, model):
        self.model = model

    def assemble(self, modules, run_dir):
        assembly_dir = run_dir / "assembly"
        assembly_dir.mkdir(exist_ok=True)
        (assembly_dir / "task.txt").write_text("assemble", encoding="utf-8")
        main_c = run_dir / "main.c"
        main_c.write_text("int main(void) { return 0; }", encoding="utf-8")
        (run_dir / "output").write_bytes(b"binary")
        return main_c, True


class TraceabilityTests(unittest.TestCase):
    def test_run_trace_records_calls_and_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = RunTrace(
                prompt="entrada",
                requested_model="modelo",
                delay=0,
                output_root=Path(temporary),
            )
            trace.configure_model("provedor/modelo", "provedor")
            trace.record_llm_call(
                "stage",
                "system",
                "user",
                "response",
                {"status": "completed"},
            )
            trace.write_text("main.c", "int main(void) { return 0; }")
            trace.finalize("completed", compiled=True)

            manifest = json.loads((trace.run_dir / "manifest.json").read_text())
            result = json.loads((trace.run_dir / "result.json").read_text())
            calls = list((trace.run_dir / "calls").glob("*.json"))

            self.assertEqual(manifest["status"], "completed")
            self.assertEqual(manifest["input"]["sha256"], sha256_text("entrada"))
            self.assertEqual(len(calls), 1)
            self.assertTrue(result["compiled"])
            self.assertIn("main.c", {item["path"] for item in result["artifacts"]})

    @patch.object(pipeline, "AssemblerHarness", FakeAssemblerHarness)
    @patch.object(pipeline, "Coder", FakeCoder)
    @patch.object(pipeline, "PromptMaker", FakePromptMaker)
    @patch.object(pipeline, "Planner", FakePlanner)
    @patch.object(pipeline, "Sanitizer", FakeSanitizer)
    @patch.object(pipeline, "LLMClient", FakeLLMClient)
    def test_pipeline_creates_a_complete_trace(self):
        with tempfile.TemporaryDirectory() as temporary:
            main_c = pipeline.run(
                "prompt original",
                model="fake/model",
                output_root=Path(temporary),
                scenario="test",
            )
            run_dir = main_c.parent
            manifest = json.loads((run_dir / "manifest.json").read_text())
            result = json.loads((run_dir / "result.json").read_text())

            self.assertEqual(manifest["status"], "completed")
            self.assertEqual(manifest["stages"]["planner"]["module_count"], 2)
            self.assertEqual(result["module_count"], 2)
            self.assertTrue((run_dir / "module_one.c").exists())
            self.assertTrue((run_dir / "modules/01_module_one/prompt.txt").exists())
            self.assertTrue((run_dir / "assembly/task.txt").exists())
            self.assertTrue((run_dir / "output").exists())

    @patch.object(pipeline, "Planner", FailingPlanner)
    @patch.object(pipeline, "Sanitizer", FakeSanitizer)
    @patch.object(pipeline, "LLMClient", FakeLLMClient)
    def test_pipeline_preserves_failed_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            output_root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "invalid planner response"):
                pipeline.run("prompt original", output_root=output_root)

            run_dirs = list(output_root.glob("run_*"))
            self.assertEqual(len(run_dirs), 1)
            result = json.loads((run_dirs[0] / "result.json").read_text())
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["error"]["type"], "ValueError")
            self.assertTrue((run_dirs[0] / "prompts/sanitized.txt").exists())


if __name__ == "__main__":
    unittest.main()
