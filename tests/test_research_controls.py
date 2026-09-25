import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.aggregate_results import wilson
from src.experimental_inputs import freeze_experimental_inputs, load_frozen_inputs
from src.integrity import seal_run, verify_seal
from src.recovery import recover_stale_runs
from src.trace import RunTrace
from src.vm_environment import snapshot_environment


class ResearchControlTests(unittest.TestCase):
    def _protocol(self, root: Path) -> Path:
        path = root / "protocol.yaml"
        path.write_text(
            "\n".join([
                'version: "1.0"',
                "status: frozen",
                'hypothesis: "h"',
                "primary_metric: functional_success_rate",
                "experiment:",
                "  id: study",
                "  scenario: sample",
                "  planned_replicates: 2",
                "conditions:",
                "  - id: fragmented",
                "models:",
                "  - model: fake/model",
                "    provider: openrouter",
                "generation_parameters:",
                "  temperature: null",
                "  top_p: null",
                "  seed: null",
                "  max_tokens: null",
                "exclusion_criteria:",
                "  - infrastructure_error",
            ]),
            encoding="utf-8",
        )
        return path

    def test_frozen_inputs_detect_tampering(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            inputs = freeze_experimental_inputs(
                root,
                "sample",
                "#define X 1",
                [{"nome": "one", "task": "one", "prototype": "int one(void);"}],
                "int main(void) { return 0; }",
                self._protocol(root),
                Path("experiments/rubrics/component-evaluation-v1.yaml"),
                "study",
                "fragmented",
                2,
                "fake/model",
                "fake/model",
                "openrouter",
                None,
                {},
            )
            loaded = load_frozen_inputs(root, inputs)
            self.assertEqual(loaded["scenario"], "sample")
            (root / "inputs" / "protocol.yaml").write_text("changed", encoding="utf-8")
            with self.assertRaises(ValueError):
                load_frozen_inputs(root, inputs)

    def test_integrity_seal_reports_modified_file(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            target = root / "result.json"
            target.write_text("{}", encoding="utf-8")
            seal_run(root)
            self.assertTrue(verify_seal(root, "run_seal.json")["valid"])
            target.write_text('{"changed": true}', encoding="utf-8")
            report = verify_seal(root, "run_seal.json")
            self.assertFalse(report["valid"])
            self.assertEqual(report["modified"], ["result.json"])

    def test_missing_manifest_is_recovered(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            run_dir = root / "run_example"
            run_dir.mkdir()
            outcomes = recover_stale_runs(root)
            self.assertEqual(outcomes[0]["reason"], "missing_manifest")
            result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "initialization_failed")

    def test_trace_initialization_failure_is_preserved(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            with patch("src.trace.collect_provenance", side_effect=RuntimeError("snapshot")):
                with self.assertRaises(RuntimeError):
                    RunTrace("prompt", "model", 0, output_root=root)
            run_dir = next(root.glob("run_*"))
            result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
            self.assertEqual(result["status"], "initialization_failed")

    def test_vm_snapshot_and_wilson_interval(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            source = root / "environment-source.json"
            source.write_text(json.dumps({
                "schema_version": "1.0",
                "execution_vm": {},
                "collector_vm": {},
                "network": {},
            }), encoding="utf-8")
            record = snapshot_environment(source, root / "evaluation")
            self.assertEqual(len(record["sha256"]), 64)
            interval = wilson(5, 10)
            self.assertLess(interval["ci95_low"], interval["rate"])
            self.assertGreater(interval["ci95_high"], interval["rate"])


if __name__ == "__main__":
    unittest.main()
