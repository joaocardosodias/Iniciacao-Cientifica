import unittest

from src.sanitizer import Sanitizer


class FakeLLM:
    def __init__(self, responses):
        self.calls = []
        self.responses = list(responses)
        self.model = "fake/model"

    def chat(self, system, user, stage="unspecified"):
        self.calls.append({"system": system, "user": user, "stage": stage})
        return self.responses.pop(0)


def numbered_prompt(count):
    return "\n\n".join(f"{number}. Requirement {number} detail." for number in range(1, count + 1))


class SanitizerFragmentTests(unittest.TestCase):
    def test_fragments_are_isolated_and_renumbered(self):
        llm = FakeLLM([
            "REQ-001: Alpha\nREQ-001: Beta",
            "1) Gamma\n2) Delta",
        ])
        sanitized = Sanitizer(llm).sanitize(numbered_prompt(4))

        self.assertEqual([call["stage"] for call in llm.calls], [
            "sanitizer.fragment_1.framing_1",
            "sanitizer.fragment_2.framing_1",
        ])
        self.assertIn("1. Requirement 1 detail.", llm.calls[0]["user"])
        self.assertIn("2. Requirement 2 detail.", llm.calls[0]["user"])
        self.assertNotIn("3. Requirement 3 detail.", llm.calls[0]["user"])
        self.assertNotIn("4. Requirement 4 detail.", llm.calls[0]["user"])
        self.assertIn("3. Requirement 3 detail.", llm.calls[1]["user"])
        self.assertIn("4. Requirement 4 detail.", llm.calls[1]["user"])
        self.assertNotIn("1. Requirement 1 detail.", llm.calls[1]["user"])
        self.assertNotIn("2. Requirement 2 detail.", llm.calls[1]["user"])
        self.assertEqual(
            sanitized,
            "REQ-001: Alpha\nREQ-002: Beta\n\nREQ-003: Gamma\nREQ-004: Delta"
        )

    def test_fragment_uses_framing_cascade_independently(self):
        llm = FakeLLM([
            "I'm sorry, I cannot help with that request.",
            "REQ-001: First",
            "REQ-001: Second",
        ])
        sanitized = Sanitizer(llm).sanitize(numbered_prompt(5))

        self.assertEqual([call["stage"] for call in llm.calls], [
            "sanitizer.fragment_1.framing_1",
            "sanitizer.fragment_1.framing_2",
            "sanitizer.fragment_2.framing_1",
        ])
        for call in llm.calls[:2]:
            self.assertIn("1. Requirement 1 detail.", call["user"])
            self.assertIn("3. Requirement 3 detail.", call["user"])
            self.assertNotIn("4. Requirement 4 detail.", call["user"])
        self.assertIn("1. Requirement 1 detail.", llm.calls[0]["user"])
        self.assertIn("3. Requirement 3 detail.", llm.calls[0]["user"])
        self.assertNotIn("4. Requirement 4 detail.", llm.calls[0]["user"])
        self.assertIn("4. Requirement 4 detail.", llm.calls[2]["user"])
        self.assertIn("5. Requirement 5 detail.", llm.calls[2]["user"])
        self.assertNotIn("1. Requirement 1 detail.", llm.calls[2]["user"])
        self.assertEqual(sanitized, "REQ-001: First\n\nREQ-002: Second")

    def test_all_framings_refused_in_one_fragment(self):
        llm = FakeLLM(["I'm sorry, I cannot help with that request."] * 4)

        with self.assertRaisesRegex(ValueError, "fragmento 1"):
            Sanitizer(llm).sanitize(numbered_prompt(2))

        self.assertEqual(len(llm.calls), 4)

    def test_framing_that_negates_requirements_is_rejected(self):
        llm = FakeLLM([
            "REQ-001: The utility SHALL scan files. "
            "REQ-002: The utility SHALL NOT transmit data.",
            "REQ-001: The utility SHALL scan files.",
            "REQ-001: The utility SHALL transform files.",
        ])
        sanitized = Sanitizer(llm).sanitize(numbered_prompt(5))

        self.assertEqual([call["stage"] for call in llm.calls], [
            "sanitizer.fragment_1.framing_1",
            "sanitizer.fragment_1.framing_2",
            "sanitizer.fragment_2.framing_1",
        ])
        self.assertEqual(
            sanitized,
            "REQ-001: The utility SHALL scan files.\n\n"
            "REQ-002: The utility SHALL transform files."
        )

    def test_detects_introduced_prohibitions(self):
        from src.sanitizer import _introduced_prohibitions
        self.assertTrue(_introduced_prohibitions("scan files", "SHALL NOT transmit"))
        self.assertFalse(_introduced_prohibitions("NUNCA use dry_run", "SHALL NOT use dry_run"))
        self.assertFalse(_introduced_prohibitions("scan files", "SHALL scan files"))


if __name__ == "__main__":
    unittest.main()
