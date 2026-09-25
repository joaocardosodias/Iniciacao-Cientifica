import json
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

import pipeline
from src.campaign import Campaign, campaign_model_slug
from src.trace import RunTrace


def create_protocol(root: Path, experiment_id: str, scenario: str, condition: str, replicas: int) -> Path:
    path = root / "protocol.yaml"
    path.write_text(
        "\n".join([
            'version: "1.0"',
            "status: frozen",
            'hypothesis: "teste"',
            "primary_metric: functional_success_rate",
            "experiment:",
            f"  id: {experiment_id}",
            f"  scenario: {scenario}",
            f"  planned_replicates: {replicas}",
            "conditions:",
            f"  - id: {condition}",
            "models:",
            "  - model: fake/model",
            "    provider: cerebras/fp16",
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


def create_run(
    output_root: Path,
    replicate: int,
    experiment_id: str,
    condition: str,
    campaign: dict,
    status: str = "completed",
) -> Path:
    trace = RunTrace(
        "cenario",
        "fake/model",
        0,
        output_root=output_root,
        experiment={"id": experiment_id, "condition": condition, "replicate": replicate},
        run_purpose="official",
        campaign=campaign,
    )
    trace.configure_model("fake/model", "openrouter")
    trace.finalize(status, compiled=status == "completed", extra={"module_count": 2})
    return trace.run_dir


class CampaignTests(unittest.TestCase):
    def test_model_slug_is_safe(self):
        self.assertEqual(
            campaign_model_slug("openai/gpt-oss-120b", "cerebras/fp16"),
            "openai_gpt-oss-120b__cerebras_fp16",
        )

    def test_create_record_resume_and_prevent_duplicate(self):
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary) / "results"
            campaign = Campaign.create(
                root,
                "estudo-01",
                "fragmented",
                "sample",
                "fake/model",
                "fake/model",
                "openrouter",
                "cerebras/fp16",
                3,
                {"temperature": 0},
            )
            self.assertEqual(campaign.pending_replicates(), [1, 2, 3])
            run_dir = create_run(
                campaign.outputs_dir,
                1,
                "estudo-01",
                "fragmented",
                campaign.run_reference(1),
            )
            campaign.record_replicate(1)
            self.assertTrue(run_dir.name.endswith("replicate_001"))
            manifest = json.loads((run_dir / "manifest.json").read_text(encoding="utf-8"))
            result = json.loads((run_dir / "result.json").read_text(encoding="utf-8"))
            self.assertEqual(manifest["run_purpose"], "official")
            self.assertEqual(result["run_purpose"], "official")
            self.assertEqual(manifest["campaign"]["path"], "../../campaign.json")
            self.assertEqual(campaign.pending_replicates(), [2, 3])
            campaign.record_initialization_failure(2, RuntimeError("failure"))
            campaign.finish_generation()
            self.assertEqual(campaign.data["status"], "interrupted")
            loaded = Campaign.find(root, "estudo-01", "fragmented", "fake/model")
            self.assertEqual(loaded.pending_replicates(), [3])
            with self.assertRaises(FileExistsError):
                Campaign.create(
                    root,
                    "estudo-01",
                    "fragmented",
                    "sample",
                    "fake/model",
                    "fake/model",
                    "openrouter",
                    "cerebras/fp16",
                    3,
                    {},
                )
            entries = [
                json.loads(line)
                for line in (root / "campaigns.jsonl").read_text(encoding="utf-8").splitlines()
            ]
            self.assertGreaterEqual(entries[-1]["revision"], 2)

    def test_official_batch_preserves_failure_and_continues(self):
        with tempfile.TemporaryDirectory() as temporary:
            results_root = Path(temporary) / "results"
            protocol = create_protocol(Path(temporary), "study", "sample", "fragmented", 3)

            def fake_run(prompt, model, **kwargs):
                replicate = kwargs["replicate"]
                run_dir = create_run(
                    kwargs["output_root"],
                    replicate,
                    kwargs["experiment_id"],
                    kwargs["condition"],
                    kwargs["campaign"],
                    "failed" if replicate == 2 else "completed",
                )
                if replicate == 2:
                    raise RuntimeError("individual failure")
                main_c = run_dir / "main.c"
                main_c.write_text("int main(void) { return 0; }", encoding="utf-8")
                return main_c

            with patch.object(pipeline, "run", side_effect=fake_run), patch.object(
                pipeline,
                "run_preflight",
                return_value={"status": "passed", "checked_at": "now"},
            ):
                campaign = pipeline.run_official_campaign(
                    prompt="cenario",
                    scenario="sample",
                    scenario_config_h="",
                    scenario_components=[
                        {"nome": "one", "task": "one", "prototype": "int one(void);"}
                    ],
                    scenario_main_c="int main(void) { return 0; }",
                    model="fake/model",
                    openrouter_provider="cerebras/fp16",
                    experiment_id="study",
                    condition="fragmented",
                    planned_replicates=3,
                    results_root=results_root,
                    protocol_path=protocol,
                    rubric_path=Path("experiments/rubrics/component-evaluation-v1.yaml"),
                )
            self.assertEqual(campaign.data["status"], "generation_completed")
            self.assertEqual(campaign.data["completed_replicates"], 2)
            self.assertEqual(campaign.data["failed_replicates"], 1)
            self.assertEqual([item["replicate"] for item in campaign.data["runs"]], [1, 2, 3])
            self.assertEqual(campaign.pending_replicates(), [])

    def test_resume_runs_only_missing_replicates(self):
        with tempfile.TemporaryDirectory() as temporary:
            results_root = Path(temporary) / "results"
            campaign = Campaign.create(
                results_root,
                "study",
                "fragmented",
                "sample",
                "fake/model",
                "fake/model",
                "openrouter",
                None,
                3,
                {"delay": 0, "temperature": 0},
            )
            campaign.data.pop("experimental_controls_required")
            campaign._save()
            create_run(
                campaign.outputs_dir,
                1,
                "study",
                "fragmented",
                campaign.run_reference(1),
            )
            campaign.record_replicate(1)
            campaign.mark_interrupted()
            observed = []

            def fake_run(prompt, model, **kwargs):
                replicate = kwargs["replicate"]
                observed.append(replicate)
                run_dir = create_run(
                    kwargs["output_root"],
                    replicate,
                    kwargs["experiment_id"],
                    kwargs["condition"],
                    kwargs["campaign"],
                )
                main_c = run_dir / "main.c"
                main_c.write_text("int main(void) { return 0; }", encoding="utf-8")
                return main_c

            with patch.object(pipeline, "run", side_effect=fake_run):
                resumed = pipeline.run_official_campaign(
                    prompt="cenario",
                    scenario="sample",
                    scenario_config_h="",
                    scenario_components=[
                        {"nome": "one", "task": "one", "prototype": "int one(void);"}
                    ],
                    scenario_main_c="int main(void) { return 0; }",
                    model="fake/model",
                    openrouter_provider=None,
                    experiment_id="study",
                    condition="fragmented",
                    planned_replicates=None,
                    results_root=results_root,
                    resume=True,
                )
            self.assertEqual(observed, [2, 3])
            self.assertEqual(resumed.data["started_replicates"], 3)
            self.assertEqual(resumed.data["completed_replicates"], 3)
            self.assertEqual(resumed.data["status"], "generation_completed")


if __name__ == "__main__":
    unittest.main()
