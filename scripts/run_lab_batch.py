import argparse
import json
import os
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from src.campaign import Campaign, campaign_model_slug
from src.trace import safe_name
from src.ui import divider, fields, header, outcome, tag
from scripts.run_lab import COMPOSE, IMAGES, sha256_file, utc_now, write_json


def collect_targets(root: Path, runs: list) -> list:
    targets = []
    for record in runs or []:
        relative = record.get("path")
        run_id = record.get("run_id")
        replicate = record.get("replicate")
        if not relative or not run_id:
            targets.append({
                "run_id": run_id,
                "replicate": replicate,
                "run_dir": None,
                "has_binary": False,
                "reason": "run sem diretorio (falha de inicializacao)",
            })
            continue
        run_dir = root / relative
        has_binary = (run_dir / "assembly" / "output").is_file()
        targets.append({
            "run_id": run_id,
            "replicate": replicate,
            "run_dir": run_dir,
            "has_binary": has_binary,
            "reason": None if has_binary else "sem binario compilado (recusa ou falha de compilacao)",
        })
    return targets


def evidence_root(out: Path, campaign: Campaign) -> Path:
    provider = campaign.data.get("inference_provider") or campaign.data.get("provider") or ""
    return (
        out
        / safe_name(campaign.data.get("experiment_id") or "")
        / "models"
        / campaign_model_slug(campaign.data.get("model") or "", provider)
        / safe_name(campaign.data.get("condition") or "")
    )


def select_campaigns(args) -> list:
    if args.all_conditions and args.condition:
        raise ValueError("--all-conditions nao pode ser combinado com --condition.")
    if not args.all_conditions and not args.condition:
        raise ValueError("Informe --condition ou --all-conditions.")
    if args.all_conditions:
        return Campaign.find_all(
            args.results_root, args.experiment_id, args.model, args.provider, include_pilots=True
        )
    return [Campaign.find(args.results_root, args.experiment_id, args.condition, args.model, args.provider)]


def build_image_env(placeholder: Path) -> dict:
    placeholder.mkdir(parents=True, exist_ok=True)
    token = placeholder / "token.json"
    manifest = placeholder / "manifest.json"
    token.write_text("{}", encoding="utf-8")
    manifest.write_text("{}", encoding="utf-8")
    env = os.environ.copy()
    env.update({
        "LAB_UID": str(os.getuid()),
        "LAB_GID": str(os.getgid()),
        "LAB_RUN_ID": "build",
        "LAB_KEY_ID": "build",
        "LAB_COLLECTOR_DIR": str(placeholder),
        "LAB_SAMPLE_DIR": str(placeholder),
        "LAB_FIXTURES_DIR": str(placeholder),
        "LAB_ENCRYPTED_DIR": str(placeholder),
        "LAB_MANIFEST": str(manifest),
        "LAB_TOKEN": str(token),
        "LAB_VERIFIER_DIR": str(placeholder),
    })
    return env


def images_present() -> bool:
    for image in IMAGES.values():
        probe = subprocess.run(
            ["docker", "image", "inspect", image],
            capture_output=True, text=True, check=False,
        )
        if probe.returncode != 0:
            return False
    return True


def ensure_images(work_dir: Path, no_build: bool) -> None:
    if images_present():
        return
    if no_build:
        raise RuntimeError("imagens ausentes e --no-build foi informado")
    env = build_image_env(work_dir / ".build-env")
    built = subprocess.run(
        ["docker", "compose", "-f", str(COMPOSE), "build"],
        cwd=str(ROOT), env=env, capture_output=True, text=True, check=False,
    )
    (work_dir / "lab_build.log").write_text((built.stdout or "") + (built.stderr or ""), encoding="utf-8")
    if built.returncode != 0:
        raise RuntimeError("build das imagens falhou")


def not_run_record(target: dict) -> dict:
    return {
        "schema_version": "1.0",
        "generation_run_id": target["run_id"],
        "replicate": target["replicate"],
        "started_at": utc_now(),
        "finished_at": utc_now(),
        "status": "not_run",
        "stages": {},
        "counts": {},
        "errors": [target["reason"]],
    }


def run_single(target: dict, args, eroot: Path) -> dict:
    run_id = target["run_id"]
    dest = eroot / run_id
    if not args.force and (dest / "metadata.json").is_file():
        return {**json.loads((dest / "metadata.json").read_text(encoding="utf-8")), "skipped": True}
    if dest.exists():
        shutil.rmtree(dest)
    if not target["has_binary"]:
        record = not_run_record(target)
        write_json(dest / "metadata.json", record)
        return record
    command = [
        sys.executable, str(ROOT / "scripts" / "run_lab.py"),
        "--run", str(target["run_dir"]),
        "--fixtures", str(args.fixtures.expanduser().resolve()),
        "--out", str(eroot),
        "--label", run_id,
        "--key-id", args.key_id,
        "--timeout", str(args.timeout),
        "--no-build",
    ]
    if args.vm_environment:
        command += ["--vm-environment", str(args.vm_environment.expanduser().resolve())]
    if args.keep:
        command += ["--keep"]
    completed = subprocess.run(command, cwd=str(ROOT), capture_output=True, text=True, check=False)
    batch_logs = eroot / "batch_logs"
    batch_logs.mkdir(parents=True, exist_ok=True)
    (batch_logs / f"{run_id}.stdout.log").write_text(completed.stdout or "", encoding="utf-8")
    (batch_logs / f"{run_id}.stderr.log").write_text(completed.stderr or "", encoding="utf-8")
    if (dest / "metadata.json").is_file():
        return json.loads((dest / "metadata.json").read_text(encoding="utf-8"))
    record = not_run_record({**target, "reason": f"run_lab falhou antes de gerar metadados (exit {completed.returncode})"})
    record["status"] = "environment_error"
    write_json(dest / "metadata.json", record)
    return record


def write_condition_summary(eroot: Path, campaign: Campaign, entries: list, fixtures: str) -> dict:
    counts = {}
    for entry in entries:
        key = "skipped" if entry.get("skipped") else entry.get("status")
        counts[key] = counts.get(key, 0) + 1
    summary = {
        "schema_version": "1.0",
        "experiment_id": campaign.data.get("experiment_id"),
        "condition": campaign.data.get("condition"),
        "context_mode": campaign.data.get("context_mode"),
        "model": campaign.data.get("model"),
        "provider": campaign.data.get("provider"),
        "inference_provider": campaign.data.get("inference_provider"),
        "campaign_id": campaign.data.get("campaign_id"),
        "campaign_path": campaign.root.name,
        "fixtures": fixtures,
        "total": len(entries),
        "counts": counts,
        "runs": entries,
        "updated_at": utc_now(),
    }
    write_json(eroot / "lab_summary.json", summary)
    summary_sha = sha256_file(eroot / "lab_summary.json")
    (eroot / "lab_summary.sha256").write_text(f"{summary_sha}  lab_summary.json\n", encoding="utf-8")
    return summary


def write_archive(eroot: Path) -> dict:
    archive = eroot.with_suffix(".tar.gz")
    with tarfile.open(archive, "w:gz") as handle:
        handle.add(eroot, arcname=eroot.name)
    return {"path": str(archive), "sha256": sha256_file(archive)}


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Executa em lote as runs de uma campanha oficial em containers isolados."
    )
    parser.add_argument("--results-root", type=Path, default=Path("results"))
    parser.add_argument("--experiment-id", required=True)
    parser.add_argument("--condition")
    parser.add_argument("--all-conditions", action="store_true")
    parser.add_argument("--model")
    parser.add_argument("--provider")
    parser.add_argument("--fixtures", type=Path, required=True)
    parser.add_argument("--vm-environment", type=Path)
    parser.add_argument("--out", type=Path, default=ROOT / "lab" / "runs", help="raiz de evidencias (espelha results/)")
    parser.add_argument("--key-id", default="key-1")
    parser.add_argument("--timeout", type=int, default=120)
    parser.add_argument("--limit", type=int, help="processa no maximo N runs no total")
    parser.add_argument("--force", action="store_true", help="reexecuta runs ja registradas")
    parser.add_argument("--no-build", action="store_true")
    parser.add_argument("--keep", action="store_true")
    parser.add_argument("--archive", action="store_true", help="gera um .tar.gz por condicao")
    args = parser.parse_args()

    if os.getuid() == 0:
        parser.error("execute como usuario sem privilegios dentro da VM")
    try:
        campaigns = select_campaigns(args)
    except (ValueError, FileNotFoundError) as error:
        parser.error(str(error))

    out = args.out.expanduser().resolve()
    remaining = args.limit if args.limit else None
    work_dir = out / ".batch"
    plans = []
    for campaign in campaigns:
        targets = collect_targets(campaign.root, campaign.data.get("runs", []))
        if remaining is not None:
            targets = targets[:remaining]
            remaining -= len(targets)
        plans.append((campaign, targets))
    executable = any(target["has_binary"] for _, targets in plans for target in targets)
    all_summaries = []
    failures = 0
    total_planned = sum(len(targets) for _, targets in plans)
    first = campaigns[0].data
    header("LABORATORIO EM LOTE")
    fields([
        ("experimento", args.experiment_id),
        ("condicao", args.condition or "todas"),
        ("modelo", args.model or first.get("model") or "-"),
        ("provider", args.provider or first.get("inference_provider") or first.get("provider") or "-"),
        ("runs", str(total_planned)),
        ("evidencia", str(out)),
    ])
    divider()
    try:
        if executable:
            ensure_images(work_dir, args.no_build)
        for campaign, targets in plans:
            eroot = evidence_root(out, campaign)
            eroot.mkdir(parents=True, exist_ok=True)
            entries = []
            for index, target in enumerate(targets, 1):
                record = run_single(target, args, eroot)
                status = "skipped" if record.get("skipped") else record.get("status")
                print(
                    f"  [{campaign.data.get('condition')}] [{index}/{len(targets)}] "
                    f"{target['run_id'].ljust(40)} {tag(status)}",
                    flush=True,
                )
                entries.append({
                    "run_id": target["run_id"],
                    "replicate": target["replicate"],
                    "status": record.get("status"),
                    "stages": record.get("stages", {}),
                    "skipped": record.get("skipped", False),
                })
            summary = write_condition_summary(eroot, campaign, entries, str(args.fixtures.expanduser().resolve()))
            if args.archive:
                archive = write_archive(eroot)
                write_json(eroot.parent / f"{eroot.name}.archive.json", archive)
                summary["archive"] = archive
            all_summaries.append(summary)
            failures += sum(
                count for key, count in summary["counts"].items() if key in {"failed", "environment_error"}
            )
    finally:
        shutil.rmtree(work_dir, ignore_errors=True)

    divider()
    for summary in all_summaries:
        detail = " | ".join(
            f"{value} {name}" for name, value in sorted(summary["counts"].items())
        )
        print(f"  {str(summary['condition']).ljust(20)} {detail or 'sem runs'}")
    lines = [f"total     : {total_planned} runs", f"evidencia : {out}"]
    outcome("passed" if not failures else "failed", lines)
    if failures:
        raise SystemExit(2)


if __name__ == "__main__":
    main()
