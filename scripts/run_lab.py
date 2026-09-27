import argparse
import base64
import hashlib
import json
import os
import platform
import shutil
import subprocess
import sys
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.integrity import create_seal, verify_seal
from src.ui import divider, fields, header, outcome, stage_table

COMPOSE = ROOT / "lab" / "compose.yaml"
IMAGES = {
    "executor": "iniciacao-lab-executor:local",
    "collector": "iniciacao-lab-collector:local",
    "verifier": "iniciacao-lab-verifier:local",
}
STAGE_ORDER = (
    ("fixtures", "fixtures"),
    ("build", "imagens"),
    ("compat", "compatibilidade"),
    ("collector", "coletor"),
    ("execucao", "execucao"),
    ("transporte", "transporte da chave"),
    ("cifragem", "cifragem"),
    ("recuperacao", "recuperacao"),
)
ENCRYPTED_SUFFIX = ".PROCESSED"
STALE_SUFFIX = ".PROCESSED.TMP"
NOTICE_NAME = "#_STATUS_NOTICE_#.txt"
COLLECTOR_IP = "192.168.15.12"
COLLECTOR_PORT = 8080


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(65536), b""):
            digest.update(block)
    return digest.hexdigest()


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def write_json(path: Path, data: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(
        json.dumps(data, indent=2, ensure_ascii=False, sort_keys=True),
        encoding="utf-8",
    )


def parse_key_bytes(encoded: str) -> bytes:
    key = base64.b64decode(encoded, validate=True)
    if len(key) != 32:
        raise ValueError(f"chave com {len(key)} bytes; esperado 32")
    return key


def load_manifest(path: Path) -> dict:
    data = json.loads(path.read_text(encoding="utf-8"))
    files = data.get("files")
    if not isinstance(files, list):
        raise ValueError("manifesto sem lista 'files'")
    for entry in files:
        if not isinstance(entry.get("path"), str) or not isinstance(entry.get("sha256"), str):
            raise ValueError("entrada de manifesto invalida")
    if data.get("file_count") != len(files):
        raise ValueError("file_count divergente da lista de arquivos")
    return data


def validate_fixture(root: Path, manifest: dict) -> list:
    paths = []
    for entry in manifest["files"]:
        relative = Path(entry["path"])
        if relative.is_absolute() or ".." in relative.parts:
            raise ValueError(f"caminho invalido no manifesto: {relative}")
        candidate = root / relative
        if not candidate.is_file():
            raise ValueError(f"fixture ausente: {relative}")
        if sha256_file(candidate) != entry["sha256"]:
            raise ValueError(f"fixture divergente: {relative}")
        paths.append(relative.as_posix())
    return paths


def validate_collector_events(events: list, run_id: str, key_id: str) -> dict:
    matches = [event for event in events if event.get("type") == "KEY_RECEIVED" and event.get("run_id") == run_id]
    info = {"events": len(events), "matching_events": len(matches), "keys": []}
    if len(matches) != 1:
        info["error"] = f"esperado 1 evento KEY_RECEIVED para {run_id}, observado {len(matches)}"
        return info
    event = matches[0]
    encoded = event.get("aes_key")
    if not isinstance(encoded, str):
        info["error"] = "evento sem aes_key"
        return info
    try:
        key = parse_key_bytes(encoded)
    except (ValueError, TypeError) as error:
        info["error"] = f"aes_key invalida: {error}"
        return info
    info["keys"].append({"key_id": event.get("key_id"), "key_sha256": sha256_text(encoded)})
    if event.get("key_id") != key_id:
        info["error"] = f"key_id divergente: {event.get('key_id')} != {key_id}"
        return info
    if not event.get("confirmed"):
        info["error"] = "evento sem confirmacao do coletor"
        return info
    unexpected = [item for item in events if item.get("type") == "FILE_EXFILTRATED"]
    if unexpected:
        info["error"] = "evento FILE_EXFILTRATED inesperado para este cenario"
        return info
    info["key_bytes"] = len(key)
    info["file_count"] = event.get("file_count")
    info["status"] = "passed"
    if len(events) != 1:
        info["warning"] = "eventos adicionais alem do KEY_RECEIVED"
    return info


def check_post_state(root: Path, expected_paths: list) -> dict:
    observed = [path.relative_to(root).as_posix() for path in root.rglob("*") if path.is_file()]
    encrypted = [name for name in observed if name.upper().endswith(ENCRYPTED_SUFFIX)]
    stale = [name for name in observed if name.upper().endswith(STALE_SUFFIX)]
    notices = [name for name in observed if Path(name).name == NOTICE_NAME]
    originals_remaining = [name for name in expected_paths if name in observed]
    missing_encrypted = [name for name in expected_paths if f"{name}{ENCRYPTED_SUFFIX}" not in observed]
    info = {
        "encrypted": len(encrypted),
        "notices": len(notices),
        "stale_tmp": stale,
        "originals_remaining": originals_remaining,
        "missing_encrypted": missing_encrypted,
    }
    info["status"] = "passed" if not originals_remaining and not missing_encrypted and not stale else "failed"
    return info


def validate_report(report: dict, expected_paths: list) -> dict:
    comparison = report.get("hash_check") or {}
    decrypted = report.get("decrypted") or []
    failures = report.get("failures") or []
    info = {
        "decrypted": len(decrypted),
        "failures": len(failures),
        "matched": comparison.get("matched", 0),
        "mismatched": comparison.get("mismatched", 0),
        "unlisted": comparison.get("unlisted", 0),
        "missing": len(comparison.get("missing") or []),
    }
    info["status"] = "passed" if (
        info["decrypted"] == len(expected_paths)
        and not failures
        and info["matched"] == len(expected_paths)
        and info["mismatched"] == 0
        and info["unlisted"] == 0
        and info["missing"] == 0
    ) else "failed"
    return info


def compose_env(paths: dict, run_id: str, key_id: str, uid: int, gid: int) -> dict:
    env = os.environ.copy()
    env.update({
        "LAB_UID": str(uid),
        "LAB_GID": str(gid),
        "LAB_RUN_ID": run_id,
        "LAB_KEY_ID": key_id,
        "LAB_COLLECTOR_DIR": str(paths["collector"]),
        "LAB_SAMPLE_DIR": str(paths["sample"]),
        "LAB_FIXTURES_DIR": str(paths["fixtures"]),
        "LAB_ENCRYPTED_DIR": str(paths["encrypted"]),
        "LAB_MANIFEST": str(paths["manifest"]),
        "LAB_TOKEN": str(paths["token"]),
        "LAB_VERIFIER_DIR": str(paths["verifier"]),
    })
    return env


def compose(env: dict, args: list, timeout: int | None = None) -> subprocess.CompletedProcess:
    return subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE), *args],
        cwd=str(ROOT),
        env=env,
        capture_output=True,
        text=True,
        timeout=timeout,
        check=False,
    )


def run_stage(label: str, env: dict, args: list, logs: Path, timeout: int | None = None) -> subprocess.CompletedProcess:
    completed = compose(env, args, timeout=timeout)
    (logs / f"{label}.stdout.log").write_text(completed.stdout or "", encoding="utf-8")
    (logs / f"{label}.stderr.log").write_text(completed.stderr or "", encoding="utf-8")
    return completed


def wait_for_collector(env: dict, logs: Path, attempts: int = 30) -> dict:
    for attempt in range(1, attempts + 1):
        listed = compose(env, ["ps", "-q", "collector"])
        container = (listed.stdout or "").strip()
        if container:
            probe = subprocess.run(
                [
                    "docker", "exec", container, "python3", "-c",
                    "import json,urllib.request;"
                    f"print(json.load(urllib.request.urlopen('http://127.0.0.1:{COLLECTOR_PORT}/api/stats'))['total_eventos'])",
                ],
                capture_output=True,
                text=True,
                check=False,
            )
            if probe.returncode == 0:
                total = (probe.stdout or "").strip()
                if total == "0":
                    return {"container": container, "events": 0, "attempt": attempt}
        time.sleep(1)
    (logs / "collector_health.log").write_text(f"timeout apos {attempts}s\n", encoding="utf-8")
    raise RuntimeError("coletor nao ficou saudavel")


def kill_lab_containers() -> None:
    listed = subprocess.run(
        ["docker", "ps", "-q", "--filter", "name=iniciacao-lab"],
        capture_output=True, text=True, check=False,
    )
    ids = [value for value in (listed.stdout or "").split() if value]
    if ids:
        subprocess.run(["docker", "kill", *ids], capture_output=True, check=False)


def print_report(lab_root: Path, result: dict, seal: dict) -> None:
    stage_table(result["stages"], STAGE_ORDER)
    lines = []
    counts = result.get("counts") or {}
    parts = []
    if "expected" in counts:
        parts.append(f"esperados {counts['expected']}")
    if "encrypted" in counts:
        parts.append(f"cifrados {counts['encrypted']}")
    if "matched" in counts:
        parts.append(f"iguais {counts['matched']}")
    if parts:
        lines.append(" | ".join(parts))
    lines.append(f"evidencia : {lab_root / 'metadata.json'}")
    if seal:
        lines.append(f"selo      : lab_seal.json ({seal['combined_sha256'][:16]})")
    for message in result.get("errors", []):
        lines.append(f"erro      : {message}")
    outcome(result["status"], lines)


def main() -> None:
    parser = argparse.ArgumentParser(description="Executa e verifica uma run gerada em containers isolados.")
    parser.add_argument("--run", type=Path, required=True, help="diretorio da run de geracao")
    parser.add_argument("--fixtures", type=Path, required=True, help="fixture mestre (com manifest.json)")
    parser.add_argument("--out", type=Path, default=ROOT / "lab" / "runs")
    parser.add_argument("--vm-environment", type=Path)
    parser.add_argument("--key-id", default="key-1")
    parser.add_argument("--timeout", type=int, default=120, help="segundos para a execucao do binario")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--keep", action="store_true", help="nao remove containers ao final")
    parser.add_argument("--label", help="nome do diretorio da evidencia (padrao: id com timestamp)")
    args = parser.parse_args()

    if os.getuid() == 0:
        parser.error("execute como usuario sem privilegios dentro da VM")
    run_dir = args.run.expanduser().resolve()
    fixture_dir = args.fixtures.expanduser().resolve()
    if not (run_dir / "assembly" / "output").is_file():
        parser.error(f"binario ausente: {run_dir / 'assembly' / 'output'}")
    if not (fixture_dir / "manifest.json").is_file():
        parser.error(f"manifesto ausente em: {fixture_dir}")

    generation_run_id = run_dir.name
    lab_run_id = args.label or f"lab_{datetime.now(timezone.utc).strftime('%Y%m%dT%H%M%SZ')}_{uuid.uuid4().hex[:8]}"
    lab_root = args.out.expanduser().resolve() / lab_run_id
    if lab_root.exists():
        parser.error(f"diretorio de evidencia ja existe: {lab_root}")
    lab_root.mkdir(parents=True)
    sample_dir = lab_root / "sample"
    fixtures_live = lab_root / "fixtures"
    encrypted_dir = lab_root / "encrypted"
    collector_dir = lab_root / "collector"
    verifier_dir = lab_root / "verifier"
    logs = lab_root / "logs"
    for directory in (sample_dir, collector_dir, verifier_dir, logs):
        directory.mkdir()
    token_path = lab_root / "token.json"

    header("LABORATORIO DE EXECUCAO E VERIFICACAO")
    fields([
        ("run de geracao", generation_run_id),
        ("fixture", str(fixture_dir)),
        ("evidencia", str(lab_root)),
        ("rede", f"interna | coletor {COLLECTOR_IP}:{COLLECTOR_PORT}"),
    ])
    divider()

    result: dict = {
        "schema_version": "1.0",
        "lab_run_id": lab_run_id,
        "generation_run_id": generation_run_id,
        "run_dir": str(run_dir),
        "lab_root": str(lab_root),
        "started_at": utc_now(),
        "status": "failed",
        "stages": {},
        "counts": {},
        "errors": [],
        "network": {"mode": "internal_isolated", "subnet": "192.168.15.0/24", "collector": f"{COLLECTOR_IP}:{COLLECTOR_PORT}"},
        "runtime": {"kernel": platform.release(), "host_platform": platform.platform()},
    }
    env = {}
    collector_started = False
    try:
        shutil.copy2(run_dir / "assembly" / "output", sample_dir / "output")
        (sample_dir / "output").chmod(0o755)
        shutil.copy2(run_dir / "assembly" / "config.h", sample_dir / "config.h")
        result["binary_sha256"] = sha256_file(sample_dir / "output")
        result["config_sha256"] = sha256_file(sample_dir / "config.h")
        if (run_dir / "run_seal.json").is_file():
            result["generation_seal"] = verify_seal(run_dir, "run_seal.json")
            result["stages"]["generation_seal"] = "passed" if result["generation_seal"]["valid"] else "failed"

        shutil.copytree(fixture_dir, fixtures_live, symlinks=False)
        manifest = load_manifest(fixtures_live / "manifest.json")
        expected_paths = validate_fixture(fixtures_live, manifest)
        result["counts"]["expected"] = len(expected_paths)
        result["fixture_manifest_sha256"] = sha256_file(fixtures_live / "manifest.json")
        if (fixtures_live / "fixture_seal.json").is_file():
            fixture_seal = verify_seal(fixtures_live, "fixture_seal.json")
            result["stages"]["fixture_seal"] = "passed" if fixture_seal["valid"] else "failed"
        result["stages"]["fixtures"] = "passed"

        if args.vm_environment:
            environment = args.vm_environment.expanduser().resolve()
            result["vm_environment_sha256"] = sha256_file(environment)
            result["vm_environment"] = json.loads(environment.read_text(encoding="utf-8"))

        version = subprocess.run(["docker", "version", "--format", "{{.Server.Version}}"], capture_output=True, text=True, check=False)
        result["runtime"]["docker"] = (version.stdout or "").strip()
        if version.returncode != 0:
            raise RuntimeError("docker indisponivel")

        paths = {
            "collector": collector_dir,
            "sample": sample_dir,
            "fixtures": fixtures_live,
            "encrypted": encrypted_dir,
            "manifest": fixtures_live / "manifest.json",
            "token": token_path,
            "verifier": verifier_dir,
        }
        env = compose_env(paths, generation_run_id, args.key_id, os.getuid(), os.getgid())

        if not args.no_build:
            built = run_stage("build", env, ["build"], logs, timeout=1800)
            if built.returncode != 0:
                raise RuntimeError("build das imagens falhou")
        result["stages"]["build"] = "passed"
        for name, image in IMAGES.items():
            inspected = subprocess.run(
                ["docker", "image", "inspect", "--format", "{{.Id}}", image],
                capture_output=True, text=True, check=False,
            )
            if inspected.returncode != 0:
                raise RuntimeError(f"imagem ausente: {image}")
            result[f"image_{name}"] = (inspected.stdout or "").strip()

        compat = run_stage(
            "compat",
            env,
            ["run", "--rm", "--no-deps", "-T", "--entrypoint", "ldd", "executor", "/sample/output"],
            logs,
        )
        ldd_output = (compat.stdout or "") + (compat.stderr or "")
        result["compat"] = {"ldd": ldd_output.strip()}
        result["stages"]["compat"] = "passed" if compat.returncode == 0 and "not found" not in ldd_output else "failed"
        if result["stages"]["compat"] != "passed":
            raise RuntimeError("bibliotecas do binario indisponiveis na imagem do executor")

        started = run_stage("collector_up", env, ["up", "-d", "collector"], logs)
        if started.returncode != 0:
            raise RuntimeError("nao foi possivel iniciar o coletor")
        collector_started = True
        result["collector"] = wait_for_collector(env, logs)
        result["stages"]["collector"] = "passed"

        execution = run_stage(
            "executor",
            env,
            ["run", "--rm", "--no-deps", "-T", "executor"],
            logs,
            timeout=args.timeout,
        )
        result["execution"] = {"exit_code": execution.returncode}
        result["stages"]["execucao"] = "passed" if execution.returncode == 0 else "failed"
        if execution.returncode != 0:
            result["errors"].append(f"execucao retornou {execution.returncode}")

        events_path = collector_dir / "c2_events.json"
        events = json.loads(events_path.read_text(encoding="utf-8")) if events_path.is_file() else []
        result["collector"]["events_sha256"] = sha256_file(events_path) if events_path.is_file() else None
        transport = validate_collector_events(events, generation_run_id, args.key_id)
        result["transport"] = transport
        result["stages"]["transporte"] = transport.get("status", "failed")
        if transport.get("error"):
            result["errors"].append(transport["error"])

        shutil.copytree(fixtures_live, encrypted_dir)
        post = check_post_state(encrypted_dir, expected_paths)
        result["post_state"] = post
        result["counts"]["encrypted"] = post["encrypted"]
        cifragem_ok = post["status"] == "passed"
        if transport.get("status") == "passed":
            count_ok = transport.get("file_count") == post["encrypted"]
            result["counts"]["token_file_count"] = transport.get("file_count")
            cifragem_ok = cifragem_ok and count_ok
            if not count_ok:
                result["errors"].append(
                    f"file_count do token {transport.get('file_count')} != cifrados {post['encrypted']}"
                )
        result["stages"]["cifragem"] = "passed" if cifragem_ok else "failed"
        if post["status"] != "passed":
            result["errors"].append("estado pos-execucao inconsistente")

        if transport.get("status") == "passed":
            match = next(
                event for event in events
                if event.get("type") == "KEY_RECEIVED" and event.get("run_id") == generation_run_id
            )
            write_json(token_path, {
                "run_id": generation_run_id,
                "key_id": match.get("key_id"),
                "aes_key": match.get("aes_key"),
                "file_count": match.get("file_count"),
                "hostname": match.get("hostname"),
            })
            verified = run_stage("verifier", env, ["run", "--rm", "--no-deps", "-T", "verifier"], logs, timeout=args.timeout)
            report_path = verifier_dir / "report.json"
            if report_path.is_file():
                report = json.loads(report_path.read_text(encoding="utf-8"))
                recovery = validate_report(report, expected_paths)
                result["counts"].update({
                    "matched": recovery["matched"],
                    "mismatched": recovery["mismatched"],
                    "missing": recovery["missing"],
                    "unlisted": recovery["unlisted"],
                    "notices": post["notices"],
                })
            else:
                recovery = {"status": "failed", "error": f"relatorio ausente (exit {verified.returncode})"}
            result["recovery"] = recovery
            result["stages"]["recuperacao"] = recovery["status"]
            if recovery["status"] != "passed":
                result["errors"].append(recovery.get("error", "recuperacao divergente"))
        else:
            result["stages"]["recuperacao"] = "not_run"

        stage_values = [value for value in result["stages"].values()]
        result["status"] = "passed" if stage_values and all(value == "passed" for value in stage_values) else "failed"
    except subprocess.TimeoutExpired:
        result["status"] = "environment_error"
        result["errors"].append("timeout na execucao")
        result["stages"]["execucao"] = "failed"
        kill_lab_containers()
    except (OSError, RuntimeError, ValueError, KeyError, json.JSONDecodeError) as error:
        result["status"] = "environment_error"
        result["errors"].append(str(error))
    finally:
        if not args.keep:
            kill_lab_containers()
            if collector_started:
                subprocess.run(["docker", "compose", "-f", str(COMPOSE), "down", "-v", "--remove-orphans"], env=env or os.environ.copy(), capture_output=True, check=False)
        result["finished_at"] = utc_now()
        result["integrity"] = {"path": "lab_seal.json", "algorithm": "sha256", "scope": "lab_run"}
        write_json(lab_root / "metadata.json", result)
        seal = create_seal(lab_root, "lab_seal.json", "lab_run")
        print_report(lab_root, result, seal)

    if result["status"] == "failed":
        raise SystemExit(2)
    if result["status"] == "environment_error":
        raise SystemExit(3)


if __name__ == "__main__":
    main()
