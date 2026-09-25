import unittest

from src.coder import Coder, _SUSPICIOUS_GUARDS


class FakeLLM:
    def __init__(self, responses):
        self.responses = list(responses)
        self.model = "fake/model"
        self.calls = []

    def chat(self, system, user, stage="unspecified", max_tokens=None):
        self.calls.append(stage)
        return self.responses.pop(0)


class CoderGuardTests(unittest.TestCase):
    def test_generate_retries_after_syntax_error(self):
        bad = '#define _GNU_SOURCE\n#include "missing.h"\nint f(void) { return 0; }\n'
        good = "#define _GNU_SOURCE\nint f(void) { return 0; }\n"
        llm = FakeLLM([bad, good])
        code = Coder(llm).generate("implement f", stage="module.f", expected_function="f")
        self.assertEqual(code, good.strip())
        self.assertEqual(llm.calls, ["module.f.attempt_1", "module.f.attempt_2"])

    def test_generate_rejects_missing_expected_function(self):
        bad = "#define _GNU_SOURCE\nint other(void) { return 0; }\n"
        llm = FakeLLM([bad, bad, bad])
        with self.assertRaisesRegex(ValueError, "missing_function"):
            Coder(llm).generate("implement f", expected_function="f")

    def test_detects_always_true_macro_guards(self):
        self.assertTrue(_SUSPICIOUS_GUARDS.search("if (SIZE_MAX > LLONG_MAX) return -1;"))
        self.assertTrue(_SUSPICIOUS_GUARDS.search("if (LLONG_MAX < SIZE_MAX) return -1;"))
        self.assertFalse(_SUSPICIOUS_GUARDS.search("if (n > SIZE_MAX - 1) return -1;"))
        self.assertFalse(_SUSPICIOUS_GUARDS.search("if (SIZE_MAX < LLONG_MAX) return -1;"))

    def test_generate_generic_retries_on_suspicious_guard(self):
        bad = (
            "#define _GNU_SOURCE\n"
            "int f(void) { if (SIZE_MAX > LLONG_MAX) return -1; return 0; }\n"
        )
        good = "#define _GNU_SOURCE\nint f(void) { return 0; }\n"
        llm = FakeLLM([bad, good])
        code = Coder(llm).generate_generic("implement f", "int f(void);")
        self.assertNotIn("LLONG_MAX", code)
        self.assertEqual(len(llm.calls), 2)

    def test_generate_generic_raises_when_always_bad(self):
        bad = (
            "#define _GNU_SOURCE\n"
            "int f(void) { if (SIZE_MAX > LLONG_MAX) return -1; return 0; }\n"
        )
        llm = FakeLLM([bad, bad, bad])
        with self.assertRaises(ValueError):
            Coder(llm).generate_generic("implement f", "int f(void);")

    def test_generate_generic_retries_on_empty_response(self):
        good = "#define _GNU_SOURCE\nint f(void) { return 0; }\n"
        llm = FakeLLM(["", good])
        code = Coder(llm).generate_generic("implement f", "int f(void);")
        self.assertIn("return 0;", code)
        self.assertEqual(len(llm.calls), 2)


if __name__ == "__main__":
    unittest.main()
