import argparse
import json
import secrets
import subprocess
import sys
import time
from functools import partial
from http.server import SimpleHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from threading import Thread

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.lab_vm import command_for_vm, config, prepare, running


def prepare_seed(state: Path, key: Path) -> Path:
    public_key = key.expanduser().read_text(encoding="utf-8").strip()
    if not public_key.startswith(("ssh-ed25519 ", "ssh-rsa ", "ecdsa-sha2-")):
        raise ValueError("Chave publica SSH invalida")
    password = secrets.token_urlsafe(40)
    password_hash = subprocess.run(
        ["openssl", "passwd", "-6", "-stdin"], input=password,
        text=True, capture_output=True, check=True,
    ).stdout.strip()
    data = {
        "autoinstall": {
            "version": 1,
            "source": {"id": "ubuntu-desktop-minimal"},
            "identity": {"hostname": "ic-lab", "username": "fragment", "password": password_hash},
            "ssh": {"install-server": True, "allow-pw": False, "authorized-keys": [public_key]},
            "storage": {"layout": {"name": "direct"}},
            "late-commands": [
                "sh -c 'printf \"fragment ALL=(ALL) NOPASSWD:ALL\\n\" > /target/etc/sudoers.d/fragment'",
                "chmod 0440 /target/etc/sudoers.d/fragment",
            ],
            "shutdown": "poweroff",
        }
    }
    seed = state / "seed"
    seed.mkdir(parents=True, exist_ok=True)
    user_data = seed / "user-data"
    user_data.write_text("#cloud-config\n" + json.dumps(data, indent=2) + "\n", encoding="utf-8")
    user_data.chmod(0o600)
    (seed / "meta-data").write_text("instance-id: ic-lab-v1\nlocal-hostname: ic-lab\n", encoding="utf-8")
    (seed / "vendor-data").write_text("", encoding="utf-8")
    return seed


def install(iso: Path, key: Path, port: int) -> None:
    disk, state, name, cpus, memory, ssh_port = config()
    iso = iso.expanduser().resolve()
    if not disk.is_file() or not iso.is_file():
        raise FileNotFoundError(f"Disco ou ISO ausente: {disk}, {iso}")
    if (state / "baseline.json").exists():
        raise RuntimeError("O disco ja foi fixado como base")
    prepare(state)
    seed = prepare_seed(state, key)
    boot = state / "boot"
    boot.mkdir(exist_ok=True)
    subprocess.run(
        ["7z", "x", "-y", f"-o{boot}", str(iso), "casper/vmlinuz", "casper/initrd"],
        check=True, capture_output=True,
    )
    server = ThreadingHTTPServer(("127.0.0.1", port), partial(SimpleHTTPRequestHandler, directory=str(seed)))
    thread = Thread(target=server.serve_forever, daemon=True)
    thread.start()
    command = command_for_vm(disk, state, name, cpus, memory, ssh_port)
    network = command.index("-netdev") + 1
    command[network] = command[network].replace("restrict=on", "restrict=off")
    command += [
        "-drive", f"file={disk},format=raw,if=ide", "-cdrom", str(iso),
        "-kernel", str(boot / "casper/vmlinuz"), "-initrd", str(boot / "casper/initrd"),
        "-append", f"boot=casper autoinstall ds=nocloud-net;s=http://10.0.2.2:{port}/ console=ttyS0,115200n8 ---",
        "-display", "none", "-pidfile", str(state / "qemu.pid"), "-daemonize",
    ]
    try:
        subprocess.run(command, check=True)
        print(f"Instalacao iniciada; log: {state / 'serial.log'}", flush=True)
        for minute in range(50):
            time.sleep(60)
            if not running(state):
                print("Instalador desligou a VM", flush=True)
                return
            print(f"Instalador em execucao: {minute + 1} min", flush=True)
        raise TimeoutError("Instalacao excedeu 50 minutos")
    finally:
        server.shutdown()
        server.server_close()


def main() -> None:
    parser = argparse.ArgumentParser(description="Instala Ubuntu 26.04 via autoinstall no QEMU")
    parser.add_argument("--iso", type=Path, required=True)
    parser.add_argument("--ssh-key", type=Path, default=Path.home() / ".ssh/lab_vm.pub")
    parser.add_argument("--seed-port", type=int, default=8124)
    parser.add_argument("--background", action="store_true")
    args = parser.parse_args()
    if args.background:
        _, state, _, _, _, _ = config()
        state.mkdir(parents=True, exist_ok=True)
        log_path = state / "install.log"
        with log_path.open("w", encoding="utf-8") as log:
            process = subprocess.Popen(
                [sys.executable, str(Path(__file__).resolve()), "--iso", str(args.iso),
                 "--ssh-key", str(args.ssh_key), "--seed-port", str(args.seed_port)],
                stdout=log, stderr=subprocess.STDOUT, start_new_session=True,
            )
        print(f"Instalador iniciado: PID {process.pid}, log {log_path}")
        return
    install(args.iso, args.ssh_key, args.seed_port)


if __name__ == "__main__":
    main()
