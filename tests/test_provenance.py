import hashlib
import json
import shutil
import subprocess
import tempfile
import unittest
from pathlib import Path

from src import provenance
from src.provenance import collect


def git(cwd: Path, *args: str) -> str:
    result = subprocess.run(
        ["git", *args],
        cwd=str(cwd),
        capture_output=True,
        text=True,
        timeout=30,
        check=True,
    )
    return result.stdout


@unittest.skipUnless(shutil.which("git"), "git indisponivel")
class ProvenanceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name)
        git(self.root, "init", "-q")
        git(self.root, "config", "user.email", "teste@example.com")
        git(self.root, "config", "user.name", "teste")
        (self.root / "pipeline.py").write_text("print('v1')\n", encoding="utf-8")
        (self.root / "src").mkdir()
        (self.root / "src" / "app.py").write_text("X = 1\n", encoding="utf-8")
        git(self.root, "add", ".")
        git(self.root, "commit", "-q", "-m", "init")

    def tearDown(self):
        self.tmp.cleanup()

    def collect(self, **kwargs):
        out = self.root / "out"
        return collect(self.root, out, **kwargs), out

    def test_clean_repo(self):
        summary, out = self.collect()
        self.assertFalse(summary["dirty"])
        self.assertRegex(summary["commit"], r"^[0-9a-f]{40}$")
        self.assertTrue(summary["branch"])
        self.assertNotIn("\n", summary["commit"])
        self.assertNotIn("\n", summary["branch"])
        self.assertEqual((out / "git.diff").read_text(), "")
        self.assertIn("pipeline.py", summary["source_hashes"])

    def test_unstaged_change(self):
        (self.root / "pipeline.py").write_text("print('v2')\n", encoding="utf-8")
        summary, out = self.collect()
        self.assertTrue(summary["dirty"])
        self.assertIn("v2", (out / "git.diff").read_text())

    def test_staged_change(self):
        (self.root / "pipeline.py").write_text("print('v3')\n", encoding="utf-8")
        git(self.root, "add", "pipeline.py")
        summary, out = self.collect()
        self.assertTrue(summary["dirty"])
        self.assertIn("v3", (out / "git.diff").read_text())

    def test_binary_diff_is_reconstructable(self):
        (self.root / "data.bin").write_bytes(bytes(range(256)))
        git(self.root, "add", "data.bin")
        git(self.root, "commit", "-q", "-m", "bin")
        (self.root / "data.bin").write_bytes(bytes(range(255, -1, -1)))
        _, out = self.collect()
        self.assertIn("GIT binary patch", (out / "git.diff").read_text())

    def test_untracked_file_is_stored(self):
        content = b"print('novo')\n"
        (self.root / "helper.py").write_bytes(content)
        summary, out = self.collect()
        untracked = json.loads((out / "untracked_files.json").read_text())
        entry = next(item for item in untracked["files"] if item["path"] == "helper.py")
        self.assertEqual(entry["sha256"], hashlib.sha256(content).hexdigest())
        self.assertEqual(entry["stored"], "untracked/helper.py")
        self.assertEqual((out / "untracked" / "helper.py").read_bytes(), content)

    def test_env_is_excluded(self):
        (self.root / ".env").write_text("CHAVE=secreta\n", encoding="utf-8")
        (self.root / ".ENV.Local").write_text("CHAVE=secreta\n", encoding="utf-8")
        (self.root / "PRIVATE.PEM").write_text("CHAVE=secreta\n", encoding="utf-8")
        summary, out = self.collect()
        untracked = json.loads((out / "untracked_files.json").read_text())
        for name in (".env", ".ENV.Local", "PRIVATE.PEM"):
            entry = next(item for item in untracked["files"] if item["path"] == name)
            self.assertEqual(entry["skipped"], "possible_secrets")
            self.assertIsNone(entry["sha256"])
            self.assertFalse((out / "untracked" / name).exists())

    def test_symlink_outside_repo_is_not_copied(self):
        with tempfile.TemporaryDirectory() as external:
            secret = Path(external) / "external.txt"
            secret.write_text("conteudo externo", encoding="utf-8")
            (self.root / "link.txt").symlink_to(secret)
            (self.root / "src" / "external.py").symlink_to(secret)
            summary, out = self.collect()
            untracked = json.loads((out / "untracked_files.json").read_text())
            for name in ("link.txt", "src/external.py"):
                entry = next(item for item in untracked["files"] if item["path"] == name)
                self.assertEqual(entry["skipped"], "symlink")
                self.assertIsNone(entry["sha256"])
                self.assertFalse((out / "untracked" / name).exists())
            self.assertNotIn("src/external.py", summary["source_hashes"])

    def test_output_dir_is_excluded(self):
        (self.root / "output").mkdir()
        (self.root / "output" / "x.txt").write_text("artefato\n", encoding="utf-8")
        summary, out = self.collect(exclude_dirs=[self.root / "output"])
        untracked = json.loads((out / "untracked_files.json").read_text())
        self.assertNotIn("output/x.txt", [item["path"] for item in untracked["files"]])

    def test_outside_git_repo(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp) / "prov"
            summary = collect(None, out)
            self.assertIsNone(summary["commit"])
            self.assertIsNone(summary["branch"])
            self.assertIsNone(summary["dirty"])
            for name in ("git.diff", "git_status.txt", "untracked_files.json", "source_hashes.json"):
                self.assertTrue((out / name).exists())

    def test_combined_sha256_is_stable(self):
        first, _ = self.collect()
        second, out = self.collect()
        self.assertEqual(first["source_combined_sha256"], second["source_combined_sha256"])
        sources = json.loads((out / "source_hashes.json").read_text())
        lines = "\n".join(
            f"{name}:{info['sha256']}" for name, info in sorted(sources["files"].items())
        )
        self.assertEqual(
            hashlib.sha256(lines.encode("utf-8")).hexdigest(),
            second["source_combined_sha256"],
        )


if __name__ == "__main__":
    unittest.main()
