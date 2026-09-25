import csv
import json
import tempfile
import unittest
from pathlib import Path

from src.campaign import Campaign
from src.evaluation import pending_runs, record_evaluation
from src.results_builder import build_results
from src.trace import RunTrace


class EvaluationResultsTests(unittest.TestCase):
    def _campaign_with_runs(self, root: Path) -> Campaign:
        campaign = Campaign.create(
            root,
            "estudo-01",
            "fragmented",
            "sample",
            "fake/model",
            "fake/model",
            "openrouter",
            "cerebras/fp16",
            2,
            {"temperature": 0},
        )
        for replicate, status in ((1, "completed"), (2, "failed")):
            trace = RunTrace(
                "cenario",
                "fake/model",
                0,
                output_root=campaign.outputs_dir,
                experiment={
                    "id": "estudo-01",
                    "condition": "fragmented",
                    "replicate": replicate,
                },
                run_purpose="official",
                campaign=campaign.run_reference(replicate),
            )
            trace.record_llm_call(
                "coder",
                "system",
                "user",
                "response",
                {
                    "status": "completed",
                    "usage": {"input_tokens": 10, "output_tokens": 5, "total_tokens": 15},
                    "cost": 0.01,
                },
            )
            trace.finalize(status, compiled=status == "completed", extra={"module_count": 1})
            campaign.record_replicate(replicate)
        campaign.finish_generation()
        return campaign

    def test_manual_evaluation_revisions_and_results(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            results_root = base / "results"
            campaign = self._campaign_with_runs(results_root)
            first = campaign.data["runs"][0]
            first_result = campaign.root / first["path"] / "result.json"
            result_before = first_result.read_bytes()
            evidence = base / "test_log.txt"
            evidence.write_text("evidence", encoding="utf-8")
            manual = record_evaluation(
                results_root,
                first["run_id"],
                "pesquisador-01",
                "partial",
                environment={"execution_vm_snapshot": "clean-v1"},
                checks=[{"description": "Iniciou", "status": "passed"}],
                evidence=[evidence],
            )
            self.assertEqual(manual["revision"], 1)
            self.assertEqual(len(manual["evidence"][0]["sha256"]), 64)
            revised = record_evaluation(
                results_root,
                first["run_id"],
                "pesquisador-01",
                "passed",
                checks=[{"description": "Iniciou", "status": "passed"}],
            )
            self.assertEqual(revised["revision"], 2)
            self.assertEqual(first_result.read_bytes(), result_before)
            run_dir = campaign.root / first["path"]
            self.assertTrue((run_dir / "evaluation/revisions/revision_0001.json").exists())
            self.assertTrue((run_dir / "evaluation/revisions/revision_0002.json").exists())
            evaluations = (campaign.root / "evaluations.jsonl").read_text().splitlines()
            self.assertEqual(len(evaluations), 2)
            self.assertEqual([item["replicate"] for item in pending_runs(campaign)], [2])

            summary = build_results(campaign)
            self.assertEqual(summary["counts"]["planned"], 2)
            self.assertEqual(summary["counts"]["evaluated"], 1)
            self.assertEqual(summary["counts"]["functional_passed"], 1)
            self.assertTrue((campaign.root / "summary.json").exists())
            self.assertTrue((campaign.root / "provenance.json").exists())
            with (campaign.root / "runs.csv").open(encoding="utf-8") as handle:
                rows = list(csv.DictReader(handle))
            self.assertEqual(len(rows), 2)
            self.assertEqual(rows[0]["functional_status"], "passed")
            self.assertEqual(rows[1]["functional_status"], "not_run")

    def test_exclusion_requires_reason(self):
        with tempfile.TemporaryDirectory() as temporary:
            results_root = Path(temporary) / "results"
            campaign = self._campaign_with_runs(results_root)
            run_id = campaign.data["runs"][0]["run_id"]
            with self.assertRaisesRegex(ValueError, "justificativa"):
                record_evaluation(
                    results_root,
                    run_id,
                    "pesquisador",
                    "environment_error",
                    include_in_analysis=False,
                )


if __name__ == "__main__":
    unittest.main()
