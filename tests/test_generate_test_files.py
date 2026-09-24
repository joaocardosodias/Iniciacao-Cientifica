import importlib.util
import tempfile
import unittest
import zipfile
from pathlib import Path

DEPS = ("openpyxl", "docx", "reportlab", "faker")


@unittest.skipUnless(all(importlib.util.find_spec(dep) for dep in DEPS),
                     "dependencias de geracao ausentes")
class GenerateTestFilesTests(unittest.TestCase):
    def test_simple_generation_creates_exact_count(self):
        from scripts import generate_test_files as generator
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            generator.generate(base, 50, workers=2, simple=True)
            files = [path for path in base.rglob("*") if path.is_file()]
            self.assertEqual(len(files), 50)

    def test_template_generation_creates_valid_files(self):
        from scripts import generate_test_files as generator
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            generator.generate(base, 40, workers=2, template=True, template_pool=5)
            files = [path for path in base.rglob("*") if path.is_file()]
            self.assertEqual(len(files), 40)
            self.assertFalse((base / ".templates").exists())
            xlsx = next(path for path in files if path.suffix == ".xlsx")
            with zipfile.ZipFile(xlsx) as archive:
                self.assertIsNone(archive.testzip())

    def test_build_tasks_reserve_unique_paths(self):
        from scripts import generate_test_files as generator
        with tempfile.TemporaryDirectory() as temporary:
            tasks = generator._build_tasks([Path(temporary)], 300)
            paths = [task[0] for task in tasks]
            self.assertEqual(len(paths), 300)
            self.assertEqual(len(set(paths)), 300)


if __name__ == "__main__":
    unittest.main()
