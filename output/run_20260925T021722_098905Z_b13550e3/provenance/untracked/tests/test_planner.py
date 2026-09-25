import json
import unittest

from src.planner import Planner


class FakeLLM:
    def __init__(self, responses):
        self.responses = iter(responses)
        self.calls = []

    def chat(self, system, user, stage):
        self.calls.append({"system": system, "user": user, "stage": stage})
        return next(self.responses)


class PlannerTests(unittest.TestCase):
    def test_retries_until_module_count_is_valid(self):
        invalid = json.dumps([
            {"nome": "one", "descricao": "primeiro"},
            {"nome": "two", "descricao": "segundo"},
        ])
        valid = json.dumps([
            {"nome": "one", "descricao": "primeiro"},
            {"nome": "two", "descricao": "segundo"},
            {"nome": "three", "descricao": "terceiro"},
        ])
        llm = FakeLLM([invalid, valid])
        modules = Planner(llm).plan("REQ-001: exemplo")
        self.assertEqual(len(modules), 3)
        self.assertEqual([call["stage"] for call in llm.calls], [
            "planner.attempt_1", "planner.attempt_2",
        ])
        self.assertIn("Previous response was invalid", llm.calls[1]["user"])

    def test_rejects_duplicate_module_names(self):
        duplicate = json.dumps([
            {"nome": "same", "descricao": "primeiro"},
            {"nome": "same", "descricao": "segundo"},
            {"nome": "third", "descricao": "terceiro"},
        ])
        llm = FakeLLM([duplicate, duplicate, duplicate])
        with self.assertRaisesRegex(ValueError, "duplicado"):
            Planner(llm).plan("REQ-001: exemplo")
        self.assertEqual(len(llm.calls), 3)

    def test_rejects_more_than_seven_modules(self):
        response = json.dumps([
            {"nome": f"module_{index}", "descricao": f"descricao {index}"}
            for index in range(8)
        ])
        llm = FakeLLM([response, response, response])
        with self.assertRaisesRegex(ValueError, "entre 3 e 7"):
            Planner(llm).plan("REQ-001: exemplo")


if __name__ == "__main__":
    unittest.main()
