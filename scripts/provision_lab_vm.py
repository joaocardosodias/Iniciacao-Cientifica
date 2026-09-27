import argparse
import io
import subprocess
import sys
import tarfile
import time
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from scripts.lab_vm import config, wait_for


def ssh_command() -> list[str]:
    _, state, _, _, _, port = config()
    return [
        "ssh", "-i", str(Path.home() / ".ssh/lab_vm"), "-p", str(port),
        "-o", "BatchMode=yes", "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={state / 'known_hosts'}",
        "fragment@127.0.0.1",
    ]


def remote(command: str, data: bytes | None = None) -> None:
    subprocess.run(ssh_command() + [command], input=data, check=True)


def source_archive() -> bytes:
    buffer = io.BytesIO()
    with tarfile.open(fileobj=buffer, mode="w:gz") as archive:
        for name in ("Cargo.toml", "Cargo.lock", ".dockerignore", "lab", "scripts", "tools", "src", "scenarios", "experiments"):
            archive.add(ROOT / name, arcname=name, filter=lambda item: None if (
                "__pycache__" in Path(item.name).parts
                or "target" in Path(item.name).parts
                or "runs" in Path(item.name).parts
                or item.name.endswith((".pyc", ".key"))
            ) else item)
    return buffer.getvalue()


def main() -> None:
    parser = argparse.ArgumentParser(description="Prepara a VM QEMU com imagens e fixtures do laboratorio")
    parser.add_argument("--resume", action="store_true")
    args = parser.parse_args()
    for attempt in range(120):
        result = subprocess.run(ssh_command() + ["true"], capture_output=True)
        if result.returncode == 0:
            break
        time.sleep(2)
    else:
        raise RuntimeError("SSH indisponivel apos 4 minutos")
    print("SSH pronto", flush=True)
    if not args.resume:
        remote("sudo env DEBIAN_FRONTEND=noninteractive apt-get update -qq")
        remote(
            "sudo env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "
            "docker.io docker-compose-v2 python3-cryptography python3-yaml python3-flask "
            "python3-venv python3-pip cargo rustc build-essential libssl-dev "
            "libcurl4-openssl-dev git ca-certificates"
        )
    remote("sudo usermod -aG docker fragment")
    remote("sudo systemctl enable --now docker")
    remote("mkdir -p ~/ic-lab && tar -xz -C ~/ic-lab", source_archive())
    for role in ("executor", "collector", "verifier"):
        print(f"Construindo imagem {role}", flush=True)
        remote(f"cd ~/ic-lab && docker build -q -f lab/Dockerfile.{role} -t iniciacao-lab-{role}:local .")
    remote(
        "cd ~/ic-lab && scripts/generate_test_files.sh ~/lab/fixture-v1 -n 5000 -w 2 "
        "&& python3 -c 'from pathlib import Path; from src.integrity import create_seal; "
        "create_seal(Path.home() / \"lab/fixture-v1\", \"fixture_seal.json\", \"master_fixture\")'"
    )
    remote(
        "python3 -c 'import platform; print(platform.freedesktop_os_release()[\"PRETTY_NAME\"])' "
        "&& docker compose version && docker image inspect "
        "iniciacao-lab-executor:local iniciacao-lab-collector:local "
        "iniciacao-lab-verifier:local --format '{{.RepoTags}}' "
        "&& test -f ~/lab/fixture-v1/fixture_seal.json"
    )
    print("Desligando VM para fixar a base", flush=True)
    subprocess.run(ssh_command() + ["sudo shutdown -h now"], capture_output=True)
    _, state, _, _, _, _ = config()
    if not wait_for(state, False, 120):
        raise RuntimeError("VM nao desligou apos provisionamento")
    print("VM preparada e desligada", flush=True)


if __name__ == "__main__":
    main()
