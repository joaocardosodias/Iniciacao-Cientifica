import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.experiment_index import append_experiment
from src.trace import RunTrace


class ExperimentIndexTests(unittest.TestCase):
    def test_relative_paths_stage_count_and_revisions(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run_test"
            manifest = {
                "stages": {"input": {"scenario": "sample"}, "planner": {"module_count": 2}},
                "software": {"git": {"source_combined_sha256": "abc"}},
            }
            result = {"run_id": "run_test", "status": "completed", "llm_calls": {"total": 1}}
            self.assertTrue(append_experiment(run_dir, manifest, result))
            self.assertFalse(append_experiment(run_dir, manifest, result))
            result["llm_calls"] = {"total": 2}
            self.assertTrue(append_experiment(run_dir, manifest, result))

            entries = [json.loads(line) for line in (run_dir.parent / "experiments.jsonl").read_text().splitlines()]
            self.assertEqual([entry["revision"] for entry in entries], [1, 2])
            self.assertEqual(entries[-1]["run_dir"], "run_test")
            self.assertEqual(entries[-1]["result_path"], "run_test/result.json")
            self.assertEqual(entries[-1]["scenario"], "sample")
            self.assertEqual(entries[-1]["module_count"], 2)
            self.assertEqual(entries[-1]["source_combined_sha256"], "abc")
            self.assertEqual(entries[-1]["llm_calls"], result["llm_calls"])
            self.assertIsNone(entries[-1]["experiment"])

            manifest["experiment"] = {"id": "study", "condition": "control", "replicate": 1}
            self.assertTrue(append_experiment(run_dir, manifest, result))
            entries = [json.loads(line) for line in (run_dir.parent / "experiments.jsonl").read_text().splitlines()]
            self.assertEqual(entries[-1]["revision"], 3)
            self.assertEqual(entries[-1]["experiment"], manifest["experiment"])

    def test_index_failure_does_not_change_terminal_status(self):
        with tempfile.TemporaryDirectory() as temporary:
            trace = RunTrace("sample", "model", 0, output_root=Path(temporary))
            with patch("src.experiment_index.append_experiment", side_effect=OSError("disk full")):
                with self.assertLogs("pipeline.experiment_index", level="WARNING"):
                    trace.finalize("completed", compiled=True)

            result = json.loads((trace.run_dir / "result.json").read_text())
            manifest = json.loads((trace.run_dir / "manifest.json").read_text())
            self.assertEqual(result["status"], "completed")
            self.assertEqual(manifest["status"], "completed")


if __name__ == "__main__":
    unittest.main()
