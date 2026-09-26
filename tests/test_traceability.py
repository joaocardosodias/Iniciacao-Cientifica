import json
import shutil
import tempfile
import unittest
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path
from unittest.mock import patch

import pipeline
from src.coder import Coder
from src.experiment_index import append_experiment
from src.recovery import recover_stale_runs
from src.trace import RunTrace, sha256_text


class FakeLLMClient:
    def __init__(self, model=None, **kwargs):
        self.model = model or "fake/model"
        self.provider = "fake"


MODULES = [
    {"nome": "module_one", "task": "primeiro modulo", "prototype": "int module_one(void);"},
    {"nome": "module_two", "task": "segundo modulo", "prototype": "int module_two(void);"},
    {"nome": "module_three", "task": "terceiro modulo", "prototype": "int module_three(void);"},
]

FAKE_CONFIG_H = "#define EXAMPLE 1\n"
FAKE_MAIN_C = "int main(void) { return 0; }\n"


class FakeCoder:
    def __init__(self, llm):
        self.llm = llm

    @staticmethod
    def user_prompt(task, prototype, global_context=None):
        return Coder.user_prompt(task, prototype, global_context)

    def generate_generic(self, task, prototype, global_context=None):
        name = prototype.split("(")[0].strip().split()[-1]
        return f"int {name}(void) {{ return 0; }}"


class FailingCoder:
    def __init__(self, llm):
        self.llm = llm

    @staticmethod
    def user_prompt(task, prototype, global_context=None):
        return Coder.user_prompt(task, prototype, global_context)

    def generate_generic(self, task, prototype, global_context=None):
        raise ValueError("invalid component response")


class InvalidCCoder:
    def __init__(self, llm):
        self.llm = llm

    @staticmethod
    def user_prompt(task, prototype, global_context=None):
        return Coder.user_prompt(task, prototype, global_context)

    def generate_generic(self, task, prototype, global_context=None):
        name = prototype.split("(")[0].strip().split()[-1]
        return f"int {name}(void) {{ invalid_token return 0; }}"


class FakeAssembler:
    def __init__(self):
        self.last_mode = "fake"
        self.last_status = "completed"

    def assemble(self, modules, run_dir, config_header=None, main_source=None):
        assembly_dir = run_dir / "assembly"
        assembly_dir.mkdir(exist_ok=True)
        main_c = run_dir / "main.c"
        main_c.write_text("int main(void) { return 0; }", encoding="utf-8")
        (run_dir / "output").write_bytes(b"binary")
        return main_c, True


class TraceabilityTests(unittest.TestCase):
    def test_index_uses_stage_module_count_when_result_lacks_it(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            cases = (
                {"planner": {"module_count": 7}},
                {"components": {"count": 9}},
                {"planner": {"module_count": 7}, "components": {"count": 9}},
            )
            for index, stages in enumerate(cases):
                run_id = f"run_{index}"
                manifest = {"stages": stages}
                result = {"run_id": run_id, "status": "failed"}
                append_experiment(root / run_id, manifest, result)
            entries = [json.loads(line) for line in (root / "experiments.jsonl").read_text().splitlines()]
            self.assertEqual([entry["module_count"] for entry in entries], [7, 9, 7])

    def test_global_index_handles_concurrent_writes_without_duplicates(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            manifest = {"created_at": "2026-01-01T00:00:00+00:00", "model": {}}

            def register(index):
                run_id = f"run_{index}"
                return append_experiment(root / run_id, manifest, {
                    "run_id": run_id, "status": "completed", "compiled": False,
                })

            with ThreadPoolExecutor(max_workers=8) as executor:
                list(executor.map(register, [0, 1, 2, 3] * 3))

            entries = [json.loads(line) for line in (root / "experiments.jsonl").read_text().splitlines()]
            self.assertEqual({entry["run_id"] for entry in entries}, {f"run_{i}" for i in range(4)})
            self.assertEqual(len(entries), 4)

    def test_run_trace_records_calls_and_hashes(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = RunTrace(
                prompt="entrada",
                requested_model="modelo",
                delay=0,
                output_root=Path(temporary),
                routing_parameters={
                    "openrouter_provider": "deepinfra",
                    "allow_fallbacks": False,
                },
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
            self.assertEqual(manifest["run_purpose"], "development")
            self.assertEqual(result["run_purpose"], "development")
            self.assertEqual(manifest["input"]["sha256"], sha256_text("entrada"))
            self.assertEqual(manifest["model"]["routing"], {
                "openrouter_provider": "deepinfra",
                "allow_fallbacks": False,
            })
            self.assertEqual(len(calls), 1)
            self.assertTrue(result["compiled"])
            self.assertIn("main.c", {item["path"] for item in result["artifacts"]})

            index_path = Path(temporary) / "experiments.jsonl"
            entries = [json.loads(line) for line in index_path.read_text().splitlines()]
            self.assertEqual(len(entries), 1)
            self.assertEqual(entries[0]["run_id"], trace.run_id)
            self.assertEqual(entries[0]["status"], "completed")
            self.assertEqual(entries[0]["run_dir"], trace.run_id)
            self.assertEqual(entries[0]["result_path"], f"{trace.run_id}/result.json")
            self.assertEqual(entries[0]["revision"], 1)
            self.assertEqual(entries[0]["llm_calls"]["total"], 1)
            self.assertNotIn("entrada", index_path.read_text())
            self.assertFalse(append_experiment(trace.run_dir, manifest, result))
            self.assertEqual(len(index_path.read_text().splitlines()), 1)

    def test_index_failure_preserves_terminal_result(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = RunTrace("entrada", "modelo", 0, output_root=Path(temporary))
            with patch("src.experiment_index.append_experiment", side_effect=OSError("sem espaco")):
                with self.assertLogs("pipeline.experiment_index", level="WARNING"):
                    trace.finalize("completed", compiled=True)

            result = json.loads((trace.run_dir / "result.json").read_text())
            manifest = json.loads((trace.run_dir / "manifest.json").read_text())
            self.assertEqual(result["status"], "completed")
            self.assertEqual(manifest["status"], "completed")
            self.assertTrue(result["compiled"])

    def test_existing_runs_are_indexed_on_recovery_scan(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            trace = RunTrace("entrada", "modelo", 0, output_root=root)
            trace.finalize("completed")
            index_path = root / "experiments.jsonl"
            index_path.unlink()

            self.assertEqual(recover_stale_runs(root), [])
            entry = json.loads(index_path.read_text())
            self.assertEqual(entry["run_id"], trace.run_id)
            self.assertEqual(entry["status"], "completed")
            self.assertEqual(recover_stale_runs(root), [])
            self.assertEqual(len(index_path.read_text().splitlines()), 1)

            result_path = trace.run_dir / "result.json"
            result = json.loads(result_path.read_text())
            result["llm_calls"]["total"] = 2
            result_path.write_text(json.dumps(result), encoding="utf-8")
            self.assertEqual(recover_stale_runs(root), [])
            entries = [json.loads(line) for line in index_path.read_text().splitlines()]
            self.assertEqual([item["revision"] for item in entries], [1, 2])
            self.assertEqual(entries[-1]["llm_calls"], result["llm_calls"])
            self.assertEqual(recover_stale_runs(root), [])
            self.assertEqual(len(index_path.read_text().splitlines()), 2)

    @patch.object(pipeline, "Assembler", FakeAssembler)
    @patch.object(pipeline, "Coder", FakeCoder)
    @patch.object(pipeline, "LLMClient", FakeLLMClient)
    def test_pipeline_creates_a_complete_trace(self):
        with tempfile.TemporaryDirectory() as temporary:
            main_c = pipeline.run(
                "descricao do cenario",
                model="fake/model",
                output_root=Path(temporary),
                scenario="test",
                scenario_config_h=FAKE_CONFIG_H,
                scenario_components=MODULES,
                scenario_main_c=FAKE_MAIN_C,
                openrouter_provider="deepinfra",
                experiment_id=" estudo-01 ",
                condition=" baseline ",
                replicate=2,
            )
            run_dir = main_c.parent
            manifest = json.loads((run_dir / "manifest.json").read_text())
            result = json.loads((run_dir / "result.json").read_text())

            self.assertEqual(manifest["status"], "completed")
            self.assertEqual(manifest["stages"]["components"]["count"], 3)
            self.assertEqual(manifest["experiment"], {
                "id": "estudo-01", "condition": "baseline", "replicate": 2,
            })
            self.assertEqual(manifest["model"]["routing"], {
                "openrouter_provider": "deepinfra",
                "allow_fallbacks": False,
            })
            self.assertEqual(result["module_count"], 3)
            entry = json.loads((Path(temporary) / "experiments.jsonl").read_text())
            self.assertEqual(entry["scenario"], "test")
            self.assertEqual(entry["experiment"], manifest["experiment"])
            self.assertEqual(entry["module_count"], 3)
            self.assertEqual(entry["source_combined_sha256"],
                             manifest["software"]["git"]["source_combined_sha256"])
            self.assertEqual(entry["run_dir"], run_dir.name)
            self.assertEqual(entry["result_path"], f"{run_dir.name}/result.json")
            self.assertTrue((run_dir / "modules/module_one.c").exists())
            self.assertTrue((run_dir / "modules/01_module_one/prompt.txt").exists())
            self.assertEqual(manifest["stages"]["assembler"]["status"], "completed")
            self.assertFalse((run_dir / "assembly/task.txt").exists())
            self.assertTrue((run_dir / "output").exists())

    @patch.object(pipeline, "Assembler", FakeAssembler)
    @patch.object(pipeline, "Coder", FailingCoder)
    @patch.object(pipeline, "LLMClient", FakeLLMClient)
    def test_pipeline_preserves_failed_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            output_root = Path(temporary)
            with self.assertRaisesRegex(ValueError, "invalid component response"):
                pipeline.run(
                    "descricao do cenario",
                    output_root=output_root,
                    scenario="test",
                    scenario_config_h=FAKE_CONFIG_H,
                    scenario_components=MODULES,
                    scenario_main_c=FAKE_MAIN_C,
                )

            run_dirs = list(output_root.glob("run_*"))
            self.assertEqual(len(run_dirs), 1)
            result = json.loads((run_dirs[0] / "result.json").read_text())
            self.assertEqual(result["status"], "failed")
            self.assertEqual(result["error"]["type"], "ValueError")
            self.assertTrue((run_dirs[0] / "prompts/components.json").exists())
            entry = json.loads((output_root / "experiments.jsonl").read_text())
            self.assertEqual(entry["status"], "failed")
            self.assertEqual(entry["error_type"], "ValueError")

    @unittest.skipUnless(shutil.which("gcc"), "gcc indisponivel")
    @patch.object(pipeline, "Coder", InvalidCCoder)
    @patch.object(pipeline, "LLMClient", FakeLLMClient)
    def test_pipeline_preserves_terminal_compile_failure(self):
        with tempfile.TemporaryDirectory() as temporary:
            output_root = Path(temporary)
            main_c = pipeline.run(
                "descricao do cenario",
                model="fake/model",
                output_root=output_root,
                scenario="test",
                scenario_config_h=FAKE_CONFIG_H,
                scenario_components=MODULES,
                scenario_main_c=FAKE_MAIN_C,
            )
            run_dir = main_c.parent.parent
            result = json.loads((run_dir / "result.json").read_text())
            assembly = json.loads((run_dir / "assembly/result.json").read_text())
            self.assertEqual(result["status"], "compile_failed")
            self.assertFalse(result["compiled"])
            self.assertEqual(assembly["status"], "compile_failed")
            self.assertFalse((run_dir / "assembly/output").exists())

    def test_invalid_experimental_identity_does_not_create_run(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            options = (
                ({"experiment_id": "  "}, "experiment-id"),
                ({"condition": "  "}, "condition"),
                ({"replicate": 0}, "replicate"),
                ({"replicate": -1}, "replicate"),
                ({"replicate": 1.5}, "replicate"),
                ({"replicate": True}, "replicate"),
            )
            for arguments, message in options:
                with self.subTest(arguments=arguments):
                    with self.assertRaisesRegex(ValueError, message):
                        pipeline.run("descricao", output_root=root,
                                     scenario_components=MODULES, **arguments)
            self.assertEqual(list(root.iterdir()), [])


if __name__ == "__main__":
    unittest.main()
