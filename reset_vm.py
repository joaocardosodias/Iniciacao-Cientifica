"""
reset_vm.py — Script de reset do ambiente de teste.

Remove todos os resquícios do teste anterior (arquivos gerados pelo
pipeline, arquivos criptografados, logs, etc.) e regenera o ambiente
limpo automaticamente, deixando a VM pronta para o próximo teste.

O que este script faz:
  1. Remove a pasta de arquivos de teste (~/Documentos_Teste ou custom)
  2. Remove a pasta output/ do pipeline (scripts gerados)
  3. Remove arquivos temporários comuns (__pycache__, .pyc, logs)
  4. Regenera o ambiente de teste limpo (chama generate_test_files.py)

Uso:
    python reset_vm.py                        # reset + regenera (padrão)
    python reset_vm.py --no-regen             # só limpa, não regenera
    python reset_vm.py --dest /outro/caminho  # pasta de teste customizada
    python reset_vm.py --count 3000           # quantidade de arquivos ao regenerar
"""

import argparse
import shutil
import subprocess
import sys
import time
from pathlib import Path

# ── Configuração dos alvos de limpeza ─────────────────────────────────────────

# Pasta raiz do projeto (onde reset_vm.py está)
PROJECT_ROOT = Path(__file__).resolve().parent

# Itens a remover dentro do projeto
PROJECT_CLEANUP_TARGETS = [
    PROJECT_ROOT / "output",          # scripts gerados pelo pipeline
    PROJECT_ROOT / "__pycache__",
    PROJECT_ROOT / "src" / "__pycache__",
]

# Extensões de arquivos temporários a varrer no projeto
TEMP_EXTENSIONS = {".pyc", ".pyo", ".log", ".tmp"}


# ── Helpers visuais ────────────────────────────────────────────────────────────

def _title(text: str):
    print(f"\n{'─' * 55}")
    print(f"  {text}")
    print(f"{'─' * 55}")


def _ok(text: str):
    print(f"  [✓] {text}")


def _skip(text: str):
    print(f"  [~] {text}")


def _warn(text: str):
    print(f"  [!] {text}")


def _confirm(prompt: str) -> bool:
    resp = input(f"\n  {prompt} [s/N]: ").strip().lower()
    return resp in ("s", "sim", "y", "yes")


# ── Limpeza ────────────────────────────────────────────────────────────────────

def clean_directory(path: Path, label: str):
    """Remove recursivamente um diretório inteiro."""
    if path.exists():
        try:
            shutil.rmtree(path)
            _ok(f"Removido: {path}  ({label})")
        except Exception as e:
            _warn(f"Falha ao remover {path}: {e}")
    else:
        _skip(f"Não encontrado (já limpo): {path}")


def clean_temp_files(root: Path):
    """Remove arquivos temporários (.pyc, .log, etc.) recursivamente."""
    removed = 0
    for ext in TEMP_EXTENSIONS:
        for f in root.rglob(f"*{ext}"):
            try:
                f.unlink()
                removed += 1
            except Exception:
                pass
    if removed:
        _ok(f"Removidos {removed} arquivo(s) temporário(s) em {root}")
    else:
        _skip("Nenhum arquivo temporário encontrado.")


def clean_output_encrypted(test_dir: Path):
    """
    Remove arquivos com extensões comuns de ransomware/criptografia
    que possam ter sido gerados dentro do diretório de teste.
    Exemplos: .enc, .locked, .crypted, .ransomware
    """
    encrypted_exts = {".enc", ".locked", ".crypted", ".ransomware", ".crypt", ".encrypted"}
    removed = 0
    if test_dir.exists():
        for ext in encrypted_exts:
            for f in test_dir.rglob(f"*{ext}"):
                try:
                    f.unlink()
                    removed += 1
                except Exception:
                    pass
    if removed:
        _ok(f"Removidos {removed} arquivo(s) criptografado(s)/residuais em {test_dir}")
    else:
        _skip("Nenhum arquivo criptografado residual encontrado.")


# ── Regeneração ────────────────────────────────────────────────────────────────

def regenerate(dest: Path, count: int):
    """Chama generate_test_files.py para recriar o ambiente de teste."""
    gen_script = PROJECT_ROOT / "generate_test_files.py"

    if not gen_script.exists():
        _warn(f"Script de geração não encontrado: {gen_script}")
        _warn("Pulando regeneração. Execute generate_test_files.py manualmente.")
        return

    print(f"\n  Regenerando {count} arquivo(s) em {dest}...")
    print(f"  (isso pode levar alguns minutos)\n")

    result = subprocess.run(
        [sys.executable, str(gen_script), str(dest), "--count", str(count)],
        text=True,
    )

    if result.returncode == 0:
        _ok("Ambiente de teste regenerado com sucesso!")
    else:
        _warn(f"Gerador terminou com código {result.returncode}.")


# ── Pipeline principal ─────────────────────────────────────────────────────────

def reset(test_dir: Path, regen: bool, count: int, force: bool):
    print("\n" + "=" * 55)
    print("   RESET DO AMBIENTE DE TESTE — INICIAÇÃO CIENTÍFICA")
    print("=" * 55)

    # Confirmação de segurança (a menos que --force)
    if not force:
        print(f"\n  Pasta de teste : {test_dir}")
        print(f"  Regenerar      : {'Sim' if regen else 'Não'}")
        print(f"  Qtd. arquivos  : {count if regen else '—'}")
        if not _confirm("Confirma o reset do ambiente?"):
            print("\n  Operação cancelada.\n")
            sys.exit(0)

    start = time.time()

    # ── 1. Remove a pasta de arquivos de teste ────────────────────
    _title("PASSO 1 — Limpando pasta de teste")
    clean_directory(test_dir, "arquivos de teste")

    # ── 2. Remove outputs do pipeline ─────────────────────────────
    _title("PASSO 2 — Limpando outputs do pipeline")
    clean_directory(PROJECT_ROOT / "output", "scripts gerados")

    # ── 3. Remove arquivos temporários do projeto ──────────────────
    _title("PASSO 3 — Limpando arquivos temporários")
    for target in PROJECT_CLEANUP_TARGETS:
        clean_directory(target, "cache Python")
    clean_temp_files(PROJECT_ROOT)

    # ── 4. Remove resquícios de criptografia no dir de teste ───────
    _title("PASSO 4 — Verificando resquícios de criptografia")
    clean_output_encrypted(test_dir)

    # ── 5. Regenera o ambiente ─────────────────────────────────────
    if regen:
        _title("PASSO 5 — Regenerando ambiente de teste")
        regenerate(test_dir, count)
    else:
        _title("PASSO 5 — Regeneração")
        _skip("Pulada (--no-regen foi especificado).")

    elapsed = time.time() - start
    print("\n" + "=" * 55)
    print(f"  ✓ Reset concluído em {elapsed:.1f}s")
    print("=" * 55 + "\n")


# ── Entry point ────────────────────────────────────────────────────────────────

def main():
    parser = argparse.ArgumentParser(
        description="Reseta o ambiente de teste da VM para um novo ciclo de experimento."
    )
    parser.add_argument(
        "--dest", "-d",
        default=str(Path.home() / "Documentos_Teste"),
        help="Pasta dos arquivos de teste (padrão: ~/Documentos_Teste)",
    )
    parser.add_argument(
        "--count", "-n",
        type=int,
        default=2000,
        help="Qtd. de arquivos a regenerar (padrão: 2000)",
    )
    parser.add_argument(
        "--no-regen",
        action="store_true",
        help="Apenas limpa, sem regenerar os arquivos de teste",
    )
    parser.add_argument(
        "--force", "-f",
        action="store_true",
        help="Pula a confirmação interativa (útil em scripts automatizados)",
    )

    args = parser.parse_args()

    reset(
        test_dir=Path(args.dest).expanduser().resolve(),
        regen=not args.no_regen,
        count=args.count,
        force=args.force,
    )


if __name__ == "__main__":
    main()
