import argparse
import hashlib
import json
import os
import socket
import subprocess
import sys
import time
from pathlib import Path


def config() -> tuple[Path, Path, str, int, int, int]:
    disk = Path(os.environ.get("LAB_VM_DISK", Path.home() / ".local/share/ic-lab/base.raw")).expanduser().resolve()
    state = Path(os.environ.get("LAB_VM_STATE", Path.home() / ".local/state/ic-lab")).expanduser()
    name = os.environ.get("LAB_VM_NAME", "IC")
    cpus = int(os.environ.get("LAB_VM_CPUS", "6"))
    memory = int(os.environ.get("LAB_VM_MEMORY_MB", "6000"))
    ssh_port = int(os.environ.get("LAB_VM_SSH_PORT", "2223"))
    if cpus < 1 or memory < 256 or not 1 <= ssh_port <= 65535:
        raise ValueError("Parametros da VM invalidos")
    return disk, state, name, cpus, memory, ssh_port


def monitor(state: Path, command: str) -> str:
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(state / "monitor.sock"))
        connection.recv(4096)
        connection.sendall((command + "\n").encode())
        return connection.recv(4096).decode(errors="replace")


def running(state: Path) -> bool:
    try:
        monitor(state, "info status")
        return True
    except (OSError, TimeoutError):
        return False


def wait_for(state: Path, active: bool, seconds: int) -> bool:
    for _ in range(seconds * 2):
        if running(state) == active:
            return True
        time.sleep(0.5)
    return running(state) == active


def digest(path: Path) -> str:
    sha = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            sha.update(chunk)
    return sha.hexdigest()


def init(size_gb: int) -> None:
    disk, state, _, _, _, _ = config()
    if size_gb < 10:
        raise ValueError("O disco precisa ter ao menos 10 GiB")
    if running(state):
        raise RuntimeError("Desligue a VM antes de criar o disco")
    disk.parent.mkdir(parents=True, exist_ok=True)
    with disk.open("xb") as handle:
        handle.truncate(size_gb * 1024 ** 3)
    print(f"Disco raw esparso criado: {disk} ({size_gb} GiB virtuais)")


def seal() -> None:
    disk, state, _, _, _, _ = config()
    if running(state):
        raise RuntimeError("Desligue a VM antes de fixar a base")
    if not disk.is_file():
        raise FileNotFoundError(disk)
    state.mkdir(parents=True, exist_ok=True)
    identifier = digest(disk)
    (state / "baseline.json").write_text(
        json.dumps({"disk": str(disk), "sha256": identifier}, indent=2) + "\n", encoding="utf-8"
    )
    print(f"Base fixada: sha256:{identifier}")


def baseline(disk: Path, state: Path) -> str:
    path = state / "baseline.json"
    if not path.is_file():
        raise FileNotFoundError("Base nao fixada; instale a VM e execute lab_vm.py seal")
    data = json.loads(path.read_text(encoding="utf-8"))
    if data["disk"] != str(disk) or data["sha256"] != digest(disk):
        raise ValueError("Disco-base diverge do identificador fixado")
    return data["sha256"]


def command_for_vm(disk: Path, state: Path, name: str, cpus: int, memory: int, ssh_port: int) -> list[str]:
    return [
        "qemu-system-x86_64", "-enable-kvm", "-machine", "pc",
        "-cpu", "host", "-smp", str(cpus), "-m", str(memory),
        "-name", name,
        "-netdev", f"user,id=labnet,restrict=on,hostfwd=tcp:127.0.0.1:{ssh_port}-:22",
        "-device", "e1000,netdev=labnet,mac=08:00:27:91:f8:e9",
        "-monitor", f"unix:{state / 'monitor.sock'},server=on,wait=off",
        "-serial", f"file:{state / 'serial.log'}",
    ]


def prepare(state: Path) -> None:
    if running(state):
        raise RuntimeError("VM ligada; exporte as evidencias e use lab-vm-reset.sh antes de iniciar outro lote")
    state.mkdir(parents=True, exist_ok=True)
    for filename in ("monitor.sock", "qemu.pid", "mode"):
        (state / filename).unlink(missing_ok=True)


def writable_command(disk: Path, state: Path, name: str, cpus: int, memory: int, ssh_port: int) -> list[str]:
    if (state / "baseline.json").exists():
        raise RuntimeError("Base ja fixada; a instalacao nao pode alterar este disco")
    prepare(state)
    command = command_for_vm(disk, state, name, cpus, memory, ssh_port)
    network = command.index("-netdev") + 1
    command[network] = command[network].replace("restrict=on", "restrict=off")
    return command + ["-drive", f"file={disk},format=raw,if=ide", "-display", "gtk"]


def install(iso: Path) -> None:
    disk, state, name, cpus, memory, ssh_port = config()
    iso = iso.expanduser().resolve()
    if not disk.is_file() or not iso.is_file():
        raise FileNotFoundError(f"Disco ou ISO nao encontrado: {disk}, {iso}")
    command = writable_command(disk, state, name, cpus, memory, ssh_port)
    command += ["-cdrom", str(iso), "-boot", "d"]
    print("Instale o sistema, habilite SSH e desligue a VM ao final. Depois execute lab_vm.py seal.")
    subprocess.run(command, check=True)


def configure() -> None:
    disk, state, name, cpus, memory, ssh_port = config()
    if not disk.is_file():
        raise FileNotFoundError(disk)
    command = writable_command(disk, state, name, cpus, memory, ssh_port)
    command += ["-boot", "c"]
    print("Prepare dependencias e fixtures, desligue o convidado e execute lab_vm.py seal.")
    subprocess.run(command, check=True)


def provision() -> None:
    disk, state, name, cpus, memory, ssh_port = config()
    if not disk.is_file():
        raise FileNotFoundError(disk)
    command = writable_command(disk, state, name, cpus, memory, ssh_port)
    command[command.index("-display") + 1] = "none"
    command += ["-boot", "c", "-pidfile", str(state / "qemu.pid"), "-daemonize"]
    subprocess.run(command, check=True)
    if not wait_for(state, True, 15):
        raise RuntimeError("QEMU iniciou sem disponibilizar o monitor")
    (state / "mode").write_text("provision\n", encoding="utf-8")
    print(f"VM {name} em preparacao: ssh -p {ssh_port} -i ~/.ssh/lab_vm fragment@127.0.0.1")
    print("Desligue o convidado pelo SSH e execute lab_vm.py seal antes de usar start")


def sync_environment(state: Path, ssh_port: int, identifier: str) -> None:
    source = Path(os.environ.get(
        "LAB_VM_ENVIRONMENT",
        Path(__file__).resolve().parents[1] / "experiments/vm-environment.ubuntu-26.04-qemu.json",
    )).expanduser().resolve()
    if not source.is_file():
        raise FileNotFoundError(f"Descricao de ambiente nao encontrada: {source}")
    description = json.loads(source.read_text(encoding="utf-8"))
    if description["vm"]["snapshot_id"] != f"sha256:{identifier}":
        raise ValueError("Identificador do ambiente nao corresponde ao disco-base")
    key = Path(os.environ.get("LAB_VM_SSH_KEY", Path.home() / ".ssh/lab_vm")).expanduser()
    options = [
        "-i", str(key), "-o", "BatchMode=yes", "-o", "ConnectTimeout=3",
        "-o", "StrictHostKeyChecking=accept-new",
        "-o", f"UserKnownHostsFile={state / 'known_hosts'}",
    ]
    for _ in range(60):
        probe = subprocess.run(
            ["ssh", "-p", str(ssh_port), *options, "fragment@127.0.0.1", "true"],
            stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        )
        if probe.returncode == 0:
            break
        time.sleep(2)
    else:
        raise RuntimeError("SSH nao ficou pronto em 2 minutos")
    subprocess.run(
        ["scp", "-P", str(ssh_port), *options, str(source),
         f"fragment@127.0.0.1:/home/fragment/ic-lab/experiments/{source.name}"],
        check=True,
    )


def start() -> None:
    disk, state, name, cpus, memory, ssh_port = config()
    if not disk.is_file():
        raise FileNotFoundError(f"Disco-base nao encontrado: {disk}; execute lab_vm.py init")
    prepare(state)
    identifier = baseline(disk, state)
    command = command_for_vm(disk, state, name, cpus, memory, ssh_port)
    command += [
        "-drive", f"file={disk},format=raw,if=ide,snapshot=on",
        "-boot", "c", "-display", "none", "-pidfile", str(state / "qemu.pid"), "-daemonize",
    ]
    subprocess.run(command, check=True)
    if not wait_for(state, True, 15):
        raise RuntimeError("QEMU iniciou sem disponibilizar o monitor")
    (state / "mode").write_text("start\n", encoding="utf-8")
    sync_environment(state, ssh_port, identifier)
    print(f"VM {name} ligada com KVM; base: sha256:{identifier}")
    print(f"SSH: ssh -p {ssh_port} -i ~/.ssh/lab_vm fragment@127.0.0.1")
    print("Alteracoes no disco sao descartadas ao desligar a VM")


def reset() -> None:
    _, state, name, _, _, _ = config()
    if not running(state):
        print(f"VM {name} desligada; proximo start inicia do disco-base limpo")
        return
    if (state / "mode").is_file() and (state / "mode").read_text().strip() == "provision":
        raise RuntimeError("VM em preparacao; desligue pelo SSH e execute lab_vm.py seal")
    if os.environ.get("LAB_RESET_CONFIRM") != "yes":
        answer = input("Exporte as evidencias antes de desligar. Confirmar? [s/N]: ").strip().lower()
        if answer not in {"s", "sim", "y", "yes"}:
            print("Cancelado")
            return
    monitor(state, "system_powerdown")
    if not wait_for(state, False, 60):
        monitor(state, "quit")
        if not wait_for(state, False, 15):
            raise RuntimeError("VM nao desligou")
    print(f"VM {name} desligada; proximo start inicia do disco-base limpo")


def status() -> None:
    disk, state, name, _, _, ssh_port = config()
    print(f"VM: {name}")
    print(f"Estado: {'ligada' if running(state) else 'desligada'}")
    print(f"Disco-base: {disk}")
    print(f"Base fixada: {(state / 'baseline.json').is_file()}")
    print(f"SSH: 127.0.0.1:{ssh_port}")


def main() -> None:
    parser = argparse.ArgumentParser(description="Gerencia a VM de laboratorio via QEMU/KVM")
    parser.add_argument("action", choices=("init", "install", "configure", "provision", "seal", "start", "reset", "status"))
    parser.add_argument("--iso", type=Path)
    parser.add_argument("--size-gb", type=int, default=25)
    args = parser.parse_args()
    try:
        if args.action == "init":
            init(args.size_gb)
        elif args.action == "install":
            if args.iso is None:
                parser.error("install exige --iso")
            install(args.iso)
        else:
            {"configure": configure, "provision": provision, "seal": seal, "start": start,
             "reset": reset, "status": status}[args.action]()
    except (OSError, ValueError, RuntimeError, KeyError, subprocess.CalledProcessError) as error:
        print(f"Erro: {error}", file=sys.stderr)
        raise SystemExit(1) from error


if __name__ == "__main__":
    main()
