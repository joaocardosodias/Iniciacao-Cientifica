"""
reset_vm.py — Limpeza completa do ambiente de teste.

Remove TODOS os resquícios de um ciclo de experimento:
  - Arquivos de teste gerados pelo generate_test_files.py
  - Arquivos criptografados pelo ransomware (.wncry, .locky, etc.)
  - Notas de resgate (LEIA_ME.txt, etc.)
  - Logs do servidor C2 (c2_events.json)
  - Entradas de persistência no crontab

Uso:
    python reset_vm.py                          # com confirmação
    python reset_vm.py --force                  # sem confirmação
    python reset_vm.py --dest /custom/pasta     # pasta de teste customizada
"""

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

# ── Constantes ─────────────────────────────────────────────────────────────────

PROJECT_ROOT = Path(__file__).resolve().parent

# Pasta criada pelo generate_test_files.py
TEST_DIR_DEFAULT = Path.home() / "Documentos_Teste"

# Pastas do sistema que o ransomware pode ter atacado
SYSTEM_DIRS = [
    Path.home() / "Documents",
    Path.home() / "Documentos",
    Path.home() / "Desktop",
    Path.home() / "Área de Trabalho",
    Path.home() / "Downloads",
    Path.home() / "Pictures",
    Path.home() / "Imagens",
    Path.home() / "Fotos",
]

# Extensões de arquivos criptografados
ENCRYPTED_EXTS = {
    ".wncry", ".locky", ".enc", ".locked",
    ".crypted", ".crypt", ".encrypted", ".ransomware",
}

# Notas de resgate que o ransomware deixa
RANSOM_NOTES = {
    "LEIA_ME.txt",
    "READ_ME.txt",
    "_INSTRUCOES_RESGATE.html",
    "HOW_TO_DECRYPT.txt",
    "YOUR_FILES_ARE_ENCRYPTED.txt",
}

# ── Helpers visuais ────────────────────────────────────────────────────────────

def _ok(msg):   print(f"  [✓] {msg}")
def _skip(msg): print(f"  [~] {msg}")
def _warn(msg): print(f"  [!] {msg}")
def _title(msg):
    print(f"\n{'─' * 55}")
    print(f"  {msg}")
    print(f"{'─' * 55}")

# ── Funções de limpeza ─────────────────────────────────────────────────────────

def _delete_dir(path: Path, label: str):
    """Remove um diretório inteiro."""
    if path.exists():
        try:
            shutil.rmtree(path)
            _ok(f"{label}: {path}")
        except Exception as e:
            _warn(f"Falha ao remover {path}: {e}")
    else:
        _skip(f"Não encontrado: {path}")


def _delete_file(path: Path, label: str = ""):
    """Remove um arquivo único."""
    if path.exists():
        try:
            path.unlink()
            _ok(f"{label or path.name}")
        except Exception as e:
            _warn(f"Falha ao remover {path}: {e}")


def clean_test_dir(test_dir: Path):
    """Remove a pasta inteira de arquivos de teste."""
    _delete_dir(test_dir, "Pasta de teste")


def clean_attack_residues():
    """
    Remove da máquina toda a sujeira deixada pelo ransomware:
    - Arquivos criptografados (.wncry, .locky, etc.)
    - Notas de resgate (LEIA_ME.txt, etc.)
    Varre as pastas padrão do sistema.
    """
    total = 0

    for directory in SYSTEM_DIRS:
        if not directory.exists():
            continue

        # Arquivos criptografados
        for ext in ENCRYPTED_EXTS:
            for f in directory.rglob(f"*{ext}"):
                try:
                    f.unlink()
                    total += 1
                except Exception:
                    pass

        # Notas de resgate
        for note_name in RANSOM_NOTES:
            for f in directory.rglob(note_name):
                try:
                    f.unlink()
                    total += 1
                except Exception:
                    pass

    if total:
        _ok(f"{total} arquivo(s) de ataque removidos das pastas do sistema.")
    else:
        _skip("Nenhum arquivo de ataque encontrado nas pastas do sistema.")


def clean_c2_log():
    """Remove o log de eventos do servidor C2."""
    _delete_file(PROJECT_ROOT / "c2_events.json", "Log do C2 (c2_events.json)")


def clean_crontab():
    """Remove entradas de persistência do crontab inseridas pelo ransomware."""
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)

        # Crontab vazio ou inexistente
        if result.returncode != 0 or not result.stdout.strip():
            _skip("Crontab vazio.")
            return

        original_lines = result.stdout.splitlines()

        # Mantém apenas linhas que NÃO referenciam o projeto ou a pasta output
        clean_lines = [
            line for line in original_lines
            if str(PROJECT_ROOT) not in line and "output/result_" not in line
        ]

        removed = len(original_lines) - len(clean_lines)

        if removed > 0:
            if clean_lines:
                subprocess.run(
                    ["crontab", "-"],
                    input="\n".join(clean_lines) + "\n",
                    text=True,
                )
            else:
                subprocess.run(["crontab", "-r"])
            _ok(f"{removed} entrada(s) de persistência removidas do crontab.")
        else:
            _skip("Nenhuma entrada de persistência no crontab.")

    except FileNotFoundError:
        _skip("Comando 'crontab' não disponível neste sistema.")
    except Exception as e:
        _warn(f"Erro ao limpar crontab: {e}")


def clean_pycache():
    """Remove caches Python do projeto."""
    for target in [
        PROJECT_ROOT / "__pycache__",
        PROJECT_ROOT / "src" / "__pycache__",
    ]:
        if target.exists():
            shutil.rmtree(target, ignore_errors=True)

    # .pyc espalhados
    count = 0
    for f in PROJECT_ROOT.rglob("*.pyc"):
        try:
            f.unlink()
            count += 1
        except Exception:
            pass

    if count:
        _ok(f"{count} arquivo(s) .pyc removidos.")


# ── Orquestrador ───────────────────────────────────────────────────────────────

def run_cleanup(test_dir: Path, force: bool):
    print("\n" + "=" * 55)
    print("   LIMPEZA COMPLETA — INICIAÇÃO CIENTÍFICA")
    print("=" * 55)

    if not force:
        print(f"\n  O que será limpo:")
        print(f"    • Pasta de teste   : {test_dir}")
        print(f"    • Arquivos .wncry, .locky, notas de resgate")
        print(f"    • Log C2           : c2_events.json")
        print(f"    • Crontab          : entradas do pipeline")

        resp = input("\n  Confirma? [s/N]: ").strip().lower()
        if resp not in ("s", "sim", "y", "yes"):
            print("\n  Cancelado.\n")
            sys.exit(0)

    start = time.time()

    _title("1 — Pasta de arquivos de teste")
    clean_test_dir(test_dir)

    _title("2 — Resquícios de ataque no sistema")
    clean_attack_residues()

    _title("3 — Log do servidor C2")
    clean_c2_log()

    _title("4 — Persistência no crontab")
    clean_crontab()

    _title("5 — Cache Python")
    clean_pycache()

    elapsed = time.time() - start
    print("\n" + "=" * 55)
    print(f"  ✓ Limpeza concluída em {elapsed:.1f}s")
    print("=" * 55 + "\n")


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Limpeza completa do ambiente de teste da VM."
    )
    parser.add_argument(
        "--dest", "-d",
        default=str(TEST_DIR_DEFAULT),
        help=f"Pasta de teste a remover (padrão: {TEST_DIR_DEFAULT})",
    )
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Pula a confirmação interativa.",
    )
    args = parser.parse_args()

    run_cleanup(
        test_dir=Path(args.dest).expanduser().resolve(),
        force=args.force,
    )


if __name__ == "__main__":
    main()
