import json
import tempfile
import unittest
from pathlib import Path

from src.assembler_harness import (
    AssemblerHarness,
    _extract_includes,
    _extract_signatures,
    _prepare_module_source,
    _remove_main_definition,
)

MODULE = """
#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>

static int helper(const char *value)
{
    if (value != NULL) {
        return 1;
    }
    return 0;
}

int public_api(const char *path, int count)
{
    for (int i = 0; i < count; i++) {
        helper(path);
    }
    return 0;
}

int main(void)
{
    return public_api("x", 1);
}

#ifdef MODULE_TEST
#include <assert.h>
static int test_only(void) { return 1; }
int main(void) { assert(test_only()); return 0; }
#endif
"""


class ExtractorTests(unittest.TestCase):
    def test_extracts_only_external_functions(self):
        signatures = _extract_signatures(MODULE)
        self.assertEqual(signatures, ["int public_api(const char *path, int count);"])

    def test_ignores_control_keywords(self):
        code = "int f(void)\n{\n    if (a != 0) { return 1; }\n    while (b) { c(); }\n}\n"
        self.assertEqual(_extract_signatures(code), ["int f(void);"])

    def test_normalizes_multiline_signature(self):
        code = "static int\nhidden(void)\n{\n    return 0;\n}\n\nlong\nrun(\n    int a,\n    char *b)\n{\n    return a;\n}\n"
        self.assertEqual(_extract_signatures(code), ["long run(int a, char *b);"])

    def test_removes_main_definition(self):
        prepared = _remove_main_definition(MODULE)
        self.assertNotIn("main(void)", prepared)
        self.assertIn("public_api", prepared)

    def test_prepare_strips_test_blocks_and_main(self):
        prepared = _prepare_module_source(MODULE)
        self.assertNotIn("MODULE_TEST", prepared)
        self.assertNotIn("test_only", prepared)
        self.assertNotIn("main(void)", prepared)

    def test_removes_main_with_string_braces(self):
        code = 'int main(void)\n{\n    puts("{ }");\n    return 0;\n}\nint keep(void) { return 1; }\n'
        prepared = _remove_main_definition(code)
        self.assertNotIn("main(void)", prepared)
        self.assertIn("keep", prepared)

    def test_includes_from_test_blocks_are_excluded(self):
        includes = _extract_includes(_prepare_module_source(MODULE))
        self.assertIn("#include <stdio.h>", includes)
        self.assertNotIn("#include <assert.h>", includes)


class NoLinkableFunctionsTests(unittest.TestCase):
    def test_assemble_skips_agent_when_no_external_functions(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run_x"
            harness = AssemblerHarness(model="openrouter/fake")
            result = harness.assemble(
                [("only_static", "static int hidden(void) { return 0; }\n")],
                run_dir,
            )
            self.assertEqual(result, (None, False))
            self.assertEqual(harness.last_status, "no_linkable_functions")
            assembly_result = json.loads((run_dir / "assembly" / "result.json").read_text())
            self.assertEqual(assembly_result["status"], "no_linkable_functions")
            self.assertEqual(assembly_result["signatures_found"], 0)


if __name__ == "__main__":
    unittest.main()
