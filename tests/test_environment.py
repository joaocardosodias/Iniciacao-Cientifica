import hashlib
import json
import os
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from src import environment
from src.trace import RunTrace


class EnvironmentTests(unittest.TestCase):
    def test_run_records_environment_and_installed_packages(self):
        secret = "PRIVATE_VALUE_DO_NOT_RECORD_81273"
        with tempfile.TemporaryDirectory() as temporary, patch.dict(
            os.environ, {"TEST_SECRET_API_KEY": secret}
        ):
            trace = RunTrace("entrada", "modelo", 0, output_root=Path(temporary))
            trace.finalize("completed")
            manifest = json.loads((trace.run_dir / "manifest.json").read_text())
            result = json.loads((trace.run_dir / "result.json").read_text())
            software = manifest["software"]
            details = trace.run_dir / software["environment_path"]
            inventory = trace.run_dir / software["packages_path"]
            recorded = json.loads(details.read_text())
            packages = json.loads(inventory.read_text())

            self.assertEqual(recorded["scope"], "pipeline_host")
            self.assertEqual(recorded["python"]["executable"], software["executable"])
            self.assertEqual(recorded["os"]["architecture"], software["architecture"])
            self.assertIn("logical_count", recorded["cpu"])
            self.assertIn("preferred_encoding", recorded["locale"])
            self.assertIn("utc_offset_seconds", recorded["timezone"])
            self.assertEqual(set(recorded["tools"]), {"gcc", "openssl", "libcurl"})
            self.assertEqual(len(packages), software["package_count"])
            self.assertEqual(len(packages), len(list(environment.importlib.metadata.distributions())))
            self.assertNotIn(secret, details.read_text() + inventory.read_text())
            artifacts = {item["path"]: item["sha256"] for item in result["artifacts"]}
            for path in (details, inventory):
                relative = path.relative_to(trace.run_dir).as_posix()
                self.assertEqual(artifacts[relative], hashlib.sha256(path.read_bytes()).hexdigest())

    def test_packages_include_every_distribution_in_stable_order(self):
        distributions = [
            SimpleNamespace(metadata={"Name": "Zeta"}, version="2"),
            SimpleNamespace(metadata={"Name": "alpha"}, version="1"),
            SimpleNamespace(metadata={"Name": "Alpha"}, version="3"),
        ]
        with patch.object(environment.importlib.metadata, "distributions", return_value=distributions):
            self.assertEqual(environment._packages(), [
                {"name": "alpha", "version": "1"},
                {"name": "Alpha", "version": "3"},
                {"name": "Zeta", "version": "2"},
            ])

    def test_missing_tools_do_not_abort_collection(self):
        with tempfile.TemporaryDirectory() as temporary, patch.object(
            environment, "_version", return_value=None
        ):
            summary = environment.collect(Path(temporary))
            details = json.loads((Path(temporary) / "environment.json").read_text())
            self.assertEqual(details["tools"], dict.fromkeys(
                ("gcc", "openssl", "libcurl")
            ))
            self.assertEqual(summary["commands"], details["tools"])
            self.assertTrue((Path(temporary) / "python_packages.json").exists())

    def test_libcurl_version_falls_back_to_curl(self):
        with patch.object(environment, "_version", side_effect=[
            None, "curl 8.2.0 (x86_64) libcurl/8.1.2 OpenSSL/3.0"
        ]):
            self.assertEqual(environment._libcurl_version(), "8.1.2")


if __name__ == "__main__":
    unittest.main()
