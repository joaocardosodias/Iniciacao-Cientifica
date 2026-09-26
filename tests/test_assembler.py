import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from src.assembler import (
    Assembler,
    _extract_includes,
    _extract_signatures,
    _prepare_module_source,
    _remove_main_definition,
    _with_standard_prelude,
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

    def test_no_drift_after_char_literals_and_loops(self):
        code = r'''
int noisy(const char *text)
{
    const char *p = text;
    while (*p != '\0') {
        if (*p == '"' || *p == '\\') { p++; }
        else if (*p < 0x20) { p++; }
        else { p++; }
    }
    return 0;
}

int after(const char *url)
{
    return url != 0;
}
'''
        self.assertEqual(_extract_signatures(code), [
            "int noisy(const char *text);",
            "int after(const char *url);",
        ])

    def test_strip_comments_preserves_urls_in_strings(self):
        code = 'const char *u = "http://10.0.0.1:8080/collect"; // c\nint x;\n'
        from src.assembler import _strip_comments
        stripped = _strip_comments(code)
        self.assertIn("http://10.0.0.1:8080/collect", stripped)
        self.assertNotIn("// c", stripped)

    def test_link_flags_from_includes(self):
        from src.assembler import _link_flags
        flags = _link_flags([
            "#include <curl/curl.h>",
            "#include <json-c/json.h>",
            "#include <pthread.h>",
        ])
        for expected in ("-lcurl", "-ljson-c", "-lpthread", "-lssl", "-lcrypto"):
            self.assertIn(expected, flags)

    def test_standard_prelude_after_gnu_source(self):
        code = '#define _GNU_SOURCE\n#include "config.h"\nint f(void) { return 0; }\n'
        result = _with_standard_prelude(code)
        self.assertTrue(result.startswith("#define _GNU_SOURCE\n"))
        self.assertLess(result.index("#include <errno.h>"), result.index('#include "config.h"'))
        self.assertLess(result.index("#include <fcntl.h>"), result.index('#include "config.h"'))

    def test_standard_prelude_adds_gnu_source_when_absent(self):
        result = _with_standard_prelude("int f(void) { return 0; }\n")
        self.assertTrue(result.startswith("#define _GNU_SOURCE\n#include <errno.h>"))


class NoLinkableFunctionsTests(unittest.TestCase):
    def test_assemble_stops_when_no_external_functions(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run_x"
            assembler = Assembler()
            result = assembler.assemble(
                [("only_static", "static int hidden(void) { return 0; }\n")],
                run_dir,
            )
            self.assertEqual(result, (None, False))
            self.assertEqual(assembler.last_status, "no_linkable_functions")
            assembly_result = json.loads((run_dir / "assembly" / "result.json").read_text())
            self.assertEqual(assembly_result["status"], "no_linkable_functions")
            self.assertEqual(assembly_result["signatures_found"], 0)


@unittest.skipUnless(shutil.which("gcc"), "gcc indisponivel")
class DeterministicAssemblyTests(unittest.TestCase):
    def test_deterministic_main_compiles(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run_det"
            config = "#define ANSWER 0\n"
            main_source = (
                '#define _GNU_SOURCE\n#include "config.h"\n'
                "int ping(void);\nint main(void) { return ping(); }\n"
            )
            module = (
                '#define _GNU_SOURCE\n#include "config.h"\n'
                "int ping(void) { return ANSWER; }\n"
            )
            assembler = Assembler()
            main_c, compiled = assembler.assemble(
                [("ping", module)],
                run_dir,
                config_header=config,
                main_source=main_source,
            )
            self.assertTrue(compiled)
            self.assertEqual(assembler.last_status, "completed")
            self.assertEqual(main_c, run_dir / "assembly" / "main.c")
            self.assertTrue((run_dir / "assembly" / "config.h").exists())
            self.assertTrue((run_dir / "assembly" / "output").exists())
            assembly_result = json.loads((run_dir / "assembly" / "result.json").read_text())
            self.assertEqual(assembly_result["mode"], "deterministic")

    def test_deterministic_compile_repairs_missing_standard_includes(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run_missing"
            config = "#define ANSWER 0\n"
            main_source = (
                '#define _GNU_SOURCE\n#include "config.h"\n'
                "int ping(void);\nint main(void) { return ping(); }\n"
            )
            module = (
                '#define _GNU_SOURCE\n#include "config.h"\n'
                "int ping(void)\n{\n"
                "    struct stat st;\n"
                "    if (errno == EINTR) { return ANSWER; }\n"
                "    if (fstatat(AT_FDCWD, \".\", &st, AT_SYMLINK_NOFOLLOW) != 0) { return ANSWER; }\n"
                "    remove(\"x\");\n"
                "    return ANSWER;\n"
                "}\n"
            )
            assembler = Assembler()
            main_c, compiled = assembler.assemble(
                [("ping", module)],
                run_dir,
                config_header=config,
                main_source=main_source,
            )
            self.assertTrue(compiled)
            self.assertEqual(assembler.last_status, "completed")
            self.assertTrue((run_dir / "assembly" / "output").exists())
            prepared = (run_dir / "assembly" / "module_01.c").read_text()
            self.assertIn("#include <errno.h>", prepared)
            self.assertIn("#include <fcntl.h>", prepared)
            self.assertIn("#include <stdio.h>", prepared)

    def test_compile_failure_is_terminal_without_repair(self):
        with tempfile.TemporaryDirectory() as temporary:
            run_dir = Path(temporary) / "run_failed"
            main_source = "int broken(void);\nint main(void) { return broken(); }\n"
            module = "int broken(void) { invalid_token return 0; }\n"
            assembler = Assembler()
            with patch.object(assembler, "_run_gcc", wraps=assembler._run_gcc) as compiler:
                main_c, compiled = assembler.assemble(
                    [("broken", module)],
                    run_dir,
                    main_source=main_source,
                )
            assembly_dir = run_dir / "assembly"
            result = json.loads((assembly_dir / "result.json").read_text())
            self.assertFalse(compiled)
            self.assertEqual(main_c, assembly_dir / "main.c")
            self.assertEqual(assembler.last_status, "compile_failed")
            self.assertEqual(result["status"], "compile_failed")
            self.assertEqual(compiler.call_count, 1)
            self.assertNotEqual(result["return_code"], 0)
            self.assertFalse(result["binary_exists"])
            self.assertFalse((assembly_dir / "task.txt").exists())


if __name__ == "__main__":
    unittest.main()
