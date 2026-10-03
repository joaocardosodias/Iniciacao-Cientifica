import re
import unittest
from pathlib import Path

TPL = Path(__file__).resolve().parents[1] / "templates" / "eternalblue" / "config.h.tpl"

_ARRAY_RE = re.compile(
    r"static const uint8_t (\w+)\[\]\s*=\s*((?:\s*\"(?:[^\"\\]|\\.)*\")+)\s*;",
    re.DOTALL,
)
_HEX_RE = re.compile(r"\\x([0-9A-Fa-f]{2})")

_SKELETON = {"DP_EXEC_PKT"}


def _parse_arrays(text: str) -> dict[str, bytes]:
    arrays: dict[str, bytes] = {}
    for name, blob in _ARRAY_RE.findall(text):
        arrays[name] = bytes(int(value, 16) for value in _HEX_RE.findall(blob))
    return arrays


class EternalBlueConfigTests(unittest.TestCase):
    def setUp(self):
        self.text = TPL.read_text(encoding="utf-8")
        self.arrays = _parse_arrays(self.text)
        self.assertIn("SMB_NEGOTIATE_PKT", self.arrays)
        self.assertIn("SMB_SESSION_SETUP_PKT", self.arrays)
        self.assertIn("SMB_TREE_CONNECT_PKT", self.arrays)
        self.assertIn("SMB_TRANS_NAMED_PIPE_PKT", self.arrays)

    def test_smb_packets_declare_correct_netbios_length(self):
        for name, data in self.arrays.items():
            if not (name.startswith("SMB_") or name.startswith("DP_")):
                continue
            if name in _SKELETON:
                continue
            declared = (data[1] << 16) | (data[2] << 8) | data[3]
            self.assertEqual(
                len(data), declared + 4,
                f"{name}: array tem {len(data)} bytes, mas o campo NetBIOS declara "
                f"{declared} (+4 = {declared + 4})",
            )

    def test_arrays_only_contain_hex_escapes(self):
        for name, blob in _ARRAY_RE.findall(self.text):
            residual = _HEX_RE.sub("", blob)
            residual = re.sub(r"[\s\"]", "", residual)
            self.assertEqual(
                residual, "",
                f"{name}: contem bytes invalidos/inesperados: {residual!r}",
            )

    def test_shellcode_arrays_are_present_and_nonempty(self):
        for name in ("KERNEL_SHELLCODE_X64_PART1", "KERNEL_SHELLCODE_X64_PART2",
                     "USERLAND_SHELLCODE_X64"):
            self.assertIn(name, self.arrays)
            self.assertGreater(len(self.arrays[name]), 0)


if __name__ == "__main__":
    unittest.main()
