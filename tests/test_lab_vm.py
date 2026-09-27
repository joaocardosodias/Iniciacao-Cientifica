import os
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from scripts import lab_vm
from scripts.lab_vm_autoinstall import prepare_seed


class LabVmTests(unittest.TestCase):
    def test_autoinstall_seed_uses_public_key(self):
        with tempfile.TemporaryDirectory() as temporary:
            base = Path(temporary)
            key = base / "access.pub"
            key.write_text("ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIFrjuyExZObBTyWm1SNmCMx6/2lWJ+mj9USIVtqHsI6I test\n")
            seed = prepare_seed(base, key)
            content = (seed / "user-data").read_text()
            self.assertIn("ubuntu-desktop-minimal", content)
            self.assertIn("ssh-ed25519", content)
            self.assertIn('"shutdown": "poweroff"', content)

    def test_init_seal_and_start_with_discarded_writes(self):
        with tempfile.TemporaryDirectory() as temporary:
            disk = Path(temporary) / "base.raw"
            state = Path(temporary) / "state"
            with patch.dict(os.environ, {"LAB_VM_DISK": str(disk), "LAB_VM_STATE": str(state)}):
                lab_vm.init(25)
                self.assertEqual(disk.stat().st_size, 25 * 1024 ** 3)
                with disk.open("r+b") as handle:
                    handle.truncate(1024)
                lab_vm.seal()
                with patch.object(lab_vm.subprocess, "run") as run, patch.object(lab_vm, "wait_for", return_value=True), patch.object(lab_vm, "sync_environment"):
                    lab_vm.start()
                args = run.call_args.args[0]
                self.assertIn(f"file={disk},format=raw,if=ide,snapshot=on", args)
                self.assertIn("-enable-kvm", args)
                self.assertIn("user,id=labnet,restrict=on,hostfwd=tcp:127.0.0.1:2223-:22", args)
                disk.write_bytes(b"alterado")
                with self.assertRaisesRegex(ValueError, "diverge"):
                    lab_vm.start()

    def test_install_requires_unsealed_disk_and_iso(self):
        with tempfile.TemporaryDirectory() as temporary:
            disk = Path(temporary) / "base.raw"
            disk.write_bytes(b"base")
            iso = Path(temporary) / "ubuntu.iso"
            iso.write_bytes(b"iso")
            state = Path(temporary) / "state"
            with patch.dict(os.environ, {"LAB_VM_DISK": str(disk), "LAB_VM_STATE": str(state)}):
                with patch.object(lab_vm.subprocess, "run") as run:
                    lab_vm.install(iso)
                args = run.call_args.args[0]
                self.assertIn("file=" + str(disk) + ",format=raw,if=ide", args)
                self.assertIn("user,id=labnet,restrict=off,hostfwd=tcp:127.0.0.1:2223-:22", args)
                self.assertIn("gtk", args)
                with patch.object(lab_vm.subprocess, "run") as run:
                    lab_vm.configure()
                self.assertIn("-boot", run.call_args.args[0])
                self.assertNotIn("-cdrom", run.call_args.args[0])
                lab_vm.seal()
                with self.assertRaisesRegex(RuntimeError, "ja fixada"):
                    lab_vm.install(iso)


if __name__ == "__main__":
    unittest.main()
