#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

typedef int (*consentimento_backup_fn)(void *contexto, const char *escopo);
typedef int (*auditoria_backup_fn)(void *contexto, const char *evento,
                                  const char *caminho, const char *detalhe);

typedef struct {
    const char *destino;
    consentimento_backup_fn consentimento;
    auditoria_backup_fn auditoria;
    void *contexto;
} configuracao_backup;

typedef struct {
    dev_t dispositivo;
    ino_t inode;
} identidade_diretorio;

typedef struct {
    identidade_diretorio *itens;
    size_t quantidade;
    size_t capacidade;
} conjunto_diretorios;

typedef struct {
    const char *rotulo;
    const char *caminho;
} raiz_backup;

static const char *const extensoes_backup[] = {
    ".xlsx", ".docx", ".pdf", ".txt", ".csv", ".jpg",
    ".png", ".db", ".backup", ".psd", ".zip", ".rar"
};

static const char mensagem_escopo_backup[] =
    "Backup local recursivo de ~/Documentos_Teste, ~/Documentos, "
    "~/Downloads, ~/Imagens e /mnt; somente arquivos com extensoes "
    "aprovadas serao copiados para o destino configurado.";

static char *juntar_caminho(const char *diretorio, const char *nome)
{
    size_t tamanho_diretorio;
    size_t tamanho_nome;
    size_t separador;
    char *resultado;

    if (diretorio == NULL || nome == NULL) {
        errno = EINVAL;
        return NULL;
    }

    tamanho_diretorio = strlen(diretorio);
    tamanho_nome = strlen(nome);
    separador = tamanho_diretorio > 0 &&
                diretorio[tamanho_diretorio - 1] != '/';

    if (tamanho_diretorio > SIZE_MAX - tamanho_nome - separador - 1) {
        errno = ENOMEM;
        return NULL;
    }

    resultado = malloc(tamanho_diretorio + separador + tamanho_nome + 1);
    if (resultado == NULL)
        return NULL;

    memcpy(resultado, diretorio, tamanho_diretorio);
    if (separador)
        resultado[tamanho_diretorio] = '/';
    memcpy(resultado + tamanho_diretorio + separador, nome, tamanho_nome + 1);
    return resultado;
}

static int registrar_evento(const configuracao_backup *configuracao,
                            const char *evento, const char *caminho,
                            const char *detalhe)
{
    if (configuracao->auditoria(configuracao->contexto, evento,
                                caminho != NULL ? caminho : "",
                                detalhe != NULL ? detalhe : "") != 0) {
        errno = EIO;
        return -1;
    }
    return 0;
}

static int registrar_falha(const configuracao_backup *configuracao,
                           const char *caminho, const char *detalhe,
                           int *houve_falha)
{
    *houve_falha = 1;
    return registrar_evento(configuracao, "falha", caminho, detalhe);
}

static int diretorio_visitado(conjunto_diretorios *visitados,
                              dev_t dispositivo, ino_t inode)
{
    size_t i;
    identidade_diretorio *novos;
    size_t capacidade;

    for (i = 0; i < visitados->quantidade; ++i) {
        if (visitados->itens[i].dispositivo == dispositivo &&
            visitados->itens[i].inode == inode)
            return 1;
    }

    if (visitados->quantidade == visitados->capacidade) {
        capacidade = visitados->capacidade == 0 ? 32 :
                     visitados->capacidade * 2;
        if (capacidade < visitados->capacidade ||
            capacidade > SIZE_MAX / sizeof(*visitados->itens)) {
            errno = ENOMEM;
            return -1;
        }
        novos = realloc(visitados->itens, capacidade * sizeof(*novos));
        if (novos == NULL)
            return -1;
        visitados->itens = novos;
        visitados->capacidade = capacidade;
    }

    visitados->itens[visitados->quantidade].dispositivo = dispositivo;
    visitados->itens[visitados->quantidade].inode = inode;
    ++visitados->quantidade;
    return 0;
}

static int extensao_aceita(const char *nome)
{
    const char *extensao;
    size_t i;

    extensao = strrchr(nome, '.');
    if (extensao == NULL)
        return 0;

    for (i = 0; i < sizeof(extensoes_backup) / sizeof(extensoes_backup[0]); ++i) {
        if (strcasecmp(extensao, extensoes_backup[i]) == 0)
            return 1;
    }
    return 0;
}

static int garantir_diretorio_destino(int diretorio_pai, const char *nome,
                                      int *diretorio_resultado)
{
    int fd;

    if (mkdirat(diretorio_pai, nome, 0700) != 0 && errno != EEXIST)
        return -1;

    fd = openat(diretorio_pai, nome,
                O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd < 0)
        return -1;

    *diretorio_resultado = fd;
    return 0;
}

static int copiar_arquivo(const configuracao_backup *configuracao,
                          const char *origem, const char *caminho_log,
                          int diretorio_destino, const char *nome_destino,
                          const struct stat *metadados, int *houve_falha)
{
    int fd_origem = -1;
    int fd_destino = -1;
    struct stat metadados_abertos;
    unsigned char buffer[65536];
    ssize_t lidos;
    size_t deslocamento;
    ssize_t escritos;
    int erro_copia = 0;
    int erro_guardado = 0;
    struct timespec tempos[2];

    fd_origem = open(origem, O_RDONLY | O_NOFOLLOW | O_CLOEXEC);
    if (fd_origem < 0) {
        erro_guardado = errno;
        goto falha;
    }

    if (fstat(fd_origem, &metadados_abertos) != 0) {
        erro_guardado = errno;
        goto falha;
    }
    if (!S_ISREG(metadados_abertos.st_mode) ||
        metadados_abertos.st_dev != metadados->st_dev ||
        metadados_abertos.st_ino != metadados->st_ino) {
        erro_guardado = ESTALE;
        goto falha;
    }

    fd_destino = openat(diretorio_destino, nome_destino,
                        O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW | O_CLOEXEC,
                        0600);
    if (fd_destino < 0) {
        erro_guardado = errno;
        goto falha;
    }

    for (;;) {
        do {
            lidos = read(fd_origem, buffer, sizeof(buffer));
        } while (lidos < 0 && errno == EINTR);

        if (lidos < 0) {
            erro_guardado = errno;
            erro_copia = 1;
            break;
        }
        if (lidos == 0)
            break;

        deslocamento = 0;
        while (deslocamento < (size_t)lidos) {
            do {
                escritos = write(fd_destino, buffer + deslocamento,
                                  (size_t)lidos - deslocamento);
            } while (escritos < 0 && errno == EINTR);

            if (escritos <= 0) {
                erro_guardado = escritos == 0 ? EIO : errno;
                erro_copia = 1;
                break;
            }
            deslocamento += (size_t)escritos;
        }
        if (erro_copia)
            break;
    }

    if (!erro_copia &&
        fchmod(fd_destino, metadados_abertos.st_mode & 07777) != 0) {
        erro_guardado = errno;
        erro_copia = 1;
    }

    if (!erro_copia) {
        tempos[0] = metadados_abertos.st_atim;
        tempos[1] = metadados_abertos.st_mtim;
        if (futimens(fd_destino, tempos) != 0) {
            erro_guardado = errno;
            erro_copia = 1;
        }
    }

    if (fd_origem >= 0) {
        if (close(fd_origem) != 0 && !erro_copia) {
            erro_guardado = errno;
            erro_copia = 1;
        }
        fd_origem = -1;
    }

    if (fd_destino >= 0) {
        if (close(fd_destino) != 0 && !erro_copia) {
            erro_guardado = errno;
            erro_copia = 1;
        }
        fd_destino = -1;
    }

    if (erro_copia) {
        (void)unlinkat(diretorio_destino, nome_destino, 0);
        errno = erro_guardado;
        goto falha;
    }

    return registrar_evento(configuracao, "sucesso", caminho_log,
                            "arquivo copiado");

falha:
    if (fd_origem >= 0)
        (void)close(fd_origem);
    if (fd_destino >= 0)
        (void)close(fd_destino);
    if (fd_destino >= 0 || erro_copia)
        (void)unlinkat(diretorio_destino, nome_destino, 0);
    errno = erro_guardado != 0 ? erro_guardado : errno;
    {
        char detalhe[128];
        int erro = errno;
        (void)snprintf(detalhe, sizeof(detalhe), "erro ao copiar: %s",
                       strerror(erro));
        return registrar_falha(configuracao, caminho_log, detalhe, houve_falha);
    }
}

static int percorrer_diretorio(const configuracao_backup *configuracao,
                               const char *origem_diretorio,
                               const char *caminho_log,
                               int diretorio_destino,
                               int fd_destino_raiz,
                               conjunto_diretorios *visitados,
                               int *houve_falha)
{
    struct stat metadados_diretorio;
    struct stat metadados_abertos;
    DIR *diretorio = NULL;
    struct dirent *entrada;
    int fd_diretorio;
    int fd_destino_filho;
    int visitado;
    int resultado = 0;
    char *origem_filho = NULL;
    char *log_filho = NULL;
    int erro_readdir;

    if (lstat(origem_diretorio, &metadados_diretorio) != 0) {
        char detalhe[128];
        (void)snprintf(detalhe, sizeof(detalhe), "lstat: %s", strerror(errno));
        return registrar_falha(configuracao, caminho_log, detalhe, houve_falha);
    }

    if (!S_ISDIR(metadados_diretorio.st_mode)) {
        return registrar_evento(configuracao, "ignorado", caminho_log,
                                "nao e um diretorio regular");
    }

    if (metadados_diretorio.st_dev == 0 && metadados_diretorio.st_ino == 0) {
        return registrar_evento(configuracao, "ignorado", caminho_log,
                                "identidade de diretorio indisponivel");
    }

    {
        struct stat metadados_destino;
        if (fstat(fd_destino_raiz, &metadados_destino) == 0 &&
            metadados_diretorio.st_dev == metadados_destino.st_dev &&
            metadados_diretorio.st_ino == metadados_destino.st_ino) {
            return registrar_evento(configuracao, "ignorado", caminho_log,
                                    "destino de backup");
        }
    }

    visitado = diretorio_visitado(visitados, metadados_diretorio.st_dev,
                                 metadados_diretorio.st_ino);
    if (visitado < 0) {
        return registrar_falha(configuracao, caminho_log,
                               "falha de alocacao ao controlar diretorios",
                               houve_falha);
    }
    if (visitado > 0)
        return registrar_evento(configuracao, "ignorado", caminho_log,
                                "diretorio ja percorrido");

    diretorio = opendir(origem_diretorio);
    if (diretorio == NULL) {
        char detalhe[128];
        (void)snprintf(detalhe, sizeof(detalhe), "opendir: %s",
                       strerror(errno));
        return registrar_falha(configuracao, caminho_log, detalhe,
                               houve_falha);
    }

    fd_diretorio = dirfd(diretorio);
    if (fd_diretorio < 0 || fstat(fd_diretorio, &metadados_abertos) != 0 ||
        !S_ISDIR(metadados_abertos.st_mode) ||
        metadados_abertos.st_dev != metadados_diretorio.st_dev ||
        metadados_abertos.st_ino != metadados_diretorio.st_ino) {
        int erro = errno != 0 ? errno : ESTALE;
        (void)closedir(diretorio);
        errno = erro;
        {
            char detalhe[128];
            (void)snprintf(detalhe, sizeof(detalhe), "diretorio mudou: %s",
                           strerror(errno));
            return registrar_falha(configuracao, caminho_log, detalhe,
                                   houve_falha);
        }
    }

    for (;;) {
        errno = 0;
        entrada = readdir(diretorio);
        if (entrada == NULL) {
            erro_readdir = errno;
            break;
        }

        if (strcmp(entrada->d_name, ".") == 0 ||
            strcmp(entrada->d_name, "..") == 0)
            continue;

        free(origem_filho);
        free(log_filho);
        origem_filho = juntar_caminho(origem_diretorio, entrada->d_name);
        log_filho = juntar_caminho(caminho_log, entrada->d_name);
        if (origem_filho == NULL || log_filho == NULL) {
            free(origem_filho);
            free(log_filho);
            origem_filho = NULL;
            log_filho = NULL;
            if (registrar_falha(configuracao, caminho_log,
                                "falha de alocacao ao montar caminho",
                                houve_falha) != 0) {
                resultado = -1;
                break;
            }
            continue;
        }

        {
            struct stat metadados;
            if (lstat(origem_filho, &metadados) != 0) {
                char detalhe[128];
                (void)snprintf(detalhe, sizeof(detalhe), "lstat: %s",
                               strerror(errno));
                if (registrar_falha(configuracao, log_filho, detalhe,
                                    houve_falha) != 0) {
                    resultado = -1;
                    break;
                }
                continue;
            }

            if (S_ISLNK(metadados.st_mode)) {
                if (registrar_evento(configuracao, "ignorado", log_filho,
                                     "link simbolico") != 0) {
                    resultado = -1;
                    break;
                }
                continue;
            }

            if (S_ISDIR(metadados.st_mode)) {
                if (garantir_diretorio_destino(diretorio_destino,
                                               entrada->d_name,
                                               &fd_destino_filho) != 0) {
                    char detalhe[128];
                    (void)snprintf(detalhe, sizeof(detalhe),
                                   "destino de diretorio: %s",
                                   strerror(errno));
                    if (registrar_falha(configuracao, log_filho, detalhe,
                                        houve_falha) != 0) {
                        resultado = -1;
                        break;
                    }
                    continue;
                }

                if (percorrer_diretorio(configuracao, origem_filho, log_filho,
                                        fd_destino_filho, fd_destino_raiz,
                                        visitados, houve_falha) != 0)
                    resultado = -1;

                if (fchmod(fd_destino_filho, metadados.st_mode & 07777) != 0) {
                    char detalhe[128];
                    (void)snprintf(detalhe, sizeof(detalhe),
                                   "fchmod do diretorio: %s",
                                   strerror(errno));
                    if (registrar_falha(configuracao, log_filho, detalhe,
                                        houve_falha) != 0)
                        resultado = -1;
                } else {
                    struct timespec tempos[2];
                    tempos[0] = metadados.st_atim;
                    tempos[1] = metadados.st_mtim;
                    if (futimens(fd_destino_filho, tempos) != 0) {
                        char detalhe[128];
                        (void)snprintf(detalhe, sizeof(detalhe),
                                       "futimens do diretorio: %s",
                                       strerror(errno));
                        if (registrar_falha(configuracao, log_filho, detalhe,
                                            houve_falha) != 0)
                            resultado = -1;
                    }
                }

                if (close(fd_destino_filho) != 0) {
                    char detalhe[128];
                    (void)snprintf(detalhe, sizeof(detalhe),
                                   "close do diretorio de destino: %s",
                                   strerror(errno));
                    if (registrar_falha(configuracao, log_filho, detalhe,
                                        houve_falha) != 0)
                        resultado = -1;
                }
                if (resultado != 0)
                    break;
                continue;
            }

            if (!S_ISREG(metadados.st_mode)) {
                if (registrar_evento(configuracao, "ignorado", log_filho,
                                     "tipo de arquivo nao suportado") != 0) {
                    resultado = -1;
                    break;
                }
                continue;
            }

            if (!extensao_aceita(entrada->d_name)) {
                if (registrar_evento(configuracao, "ignorado", log_filho,
                                     "extensao nao aprovada") != 0) {
                    resultado = -1;
                    break;
                }
                continue;
            }

            if (copiar_arquivo(configuracao, origem_filho, log_filho,
                               diretorio_destino, entrada->d_name,
                               &metadados, houve_falha) != 0) {
                resultado = -1;
                break;
            }
        }
    }

    free(origem_filho);
    free(log_filho);

    if (erro_readdir != 0) {
        char detalhe[128];
        (void)snprintf(detalhe, sizeof(detalhe), "readdir: %s",
                       strerror(erro_readdir));
        if (registrar_falha(configuracao, caminho_log, detalhe,
                            houve_falha) != 0)
            resultado = -1;
    }

    if (closedir(diretorio) != 0) {
        char detalhe[128];
        (void)snprintf(detalhe, sizeof(detalhe), "closedir: %s",
                       strerror(errno));
        if (registrar_falha(configuracao, caminho_log, detalhe,
                            houve_falha) != 0)
            resultado = -1;
    }

    return resultado;
}

 
int enumeracao_e_captura_de_arquivos(const configuracao_backup *configuracao)
{
    const char *home;
    const char *nomes_home[] = {
        "Documentos_Teste", "Documentos", "Downloads", "Imagens"
    };
    const char *rotulos_home[] = {
        "Documentos_Teste", "Documentos", "Downloads", "Imagens"
    };
    raiz_backup raizes[5];
    size_t quantidade_raizes = 0;
    size_t i;
    char *caminhos_home[4] = { NULL, NULL, NULL, NULL };
    int fd_destino = -1;
    int fd_raiz_destino = -1;
    struct stat metadados_destino;
    conjunto_diretorios visitados = { NULL, 0, 0 };
    int houve_falha = 0;
    int consentimento;

    if (configuracao == NULL || configuracao->destino == NULL ||
        configuracao->destino[0] == '\0' ||
        configuracao->consentimento == NULL ||
        configuracao->auditoria == NULL) {
        errno = EINVAL;
        return -1;
    }

    consentimento = configuracao->consentimento(configuracao->contexto,
                                                 mensagem_escopo_backup);
    if (consentimento <= 0) {
        if (registrar_evento(configuracao,
                             consentimento == 0 ? "consentimento_negado" :
                                                  "falha",
                             "", consentimento == 0 ?
                             "varredura nao iniciada" :
                             "erro ao obter consentimento") != 0)
            return -1;
        return consentimento == 0 ? 1 : -1;
    }

    if (registrar_evento(configuracao, "consentimento_concedido", "",
                         "escopo de backup local aprovado") != 0 ||
        registrar_evento(configuracao, "execucao_iniciada", "",
                         "backup local") != 0)
        return -1;

    if (lstat(configuracao->destino, &metadados_destino) != 0 ||
        !S_ISDIR(metadados_destino.st_mode)) {
        int erro = errno != 0 ? errno : ENOTDIR;
        char detalhe[128];
        (void)snprintf(detalhe, sizeof(detalhe), "destino indisponivel: %s",
                       strerror(erro));
        if (registrar_falha(configuracao, configuracao->destino, detalhe,
                            &houve_falha) != 0)
            return -1;
        (void)registrar_evento(configuracao, "execucao_finalizada", "",
                               "nenhum diretorio de origem percorrido");
        return 1;
    }

    fd_destino = open(configuracao->destino,
                      O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (fd_destino < 0 || fstat(fd_destino, &metadados_destino) != 0 ||
        !S_ISDIR(metadados_destino.st_mode)) {
        int erro = errno != 0 ? errno : ENOTDIR;
        char detalhe[128];
        if (fd_destino >= 0)
            (void)close(fd_destino);
        (void)snprintf(detalhe, sizeof(detalhe), "abertura do destino: %s",
                       strerror(erro));
        if (registrar_falha(configuracao, configuracao->destino, detalhe,
                            &houve_falha) != 0)
            return -1;
        (void)registrar_evento(configuracao, "execucao_finalizada", "",
                               "nenhum diretorio de origem percorrido");
        return 1;
    }

    home = getenv("HOME");
    if (home != NULL && home[0] != '\0') {
        for (i = 0; i < 4; ++i) {
            caminhos_home[i] = juntar_caminho(home, nomes_home[i]);
            if (caminhos_home[i] == NULL) {
                char detalhe[128];
                (void)snprintf(detalhe, sizeof(detalhe),
                               "falha de alocacao: %s", strerror(errno));
                if (registrar_falha(configuracao, nomes_home[i], detalhe,
                                    &houve_falha) != 0)
                    goto falha_auditoria;
                continue;
            }
            raizes[quantidade_raizes].rotulo = rotulos_home[i];
            raizes[quantidade_raizes].caminho = caminhos_home[i];
            ++quantidade_raizes;
        }
    } else {
        houve_falha = 1;
        if (registrar_evento(configuracao, "falha", "HOME",
                             "variavel HOME ausente ou vazia") != 0)
            goto falha_auditoria;
    }

    raizes[quantidade_raizes].rotulo = "mnt";
    raizes[quantidade_raizes].caminho = "/mnt";
    ++quantidade_raizes;

    for (i = 0; i < quantidade_raizes; ++i) {
        int resultado_raiz;
        char *caminho_log = juntar_caminho("", raizes[i].rotulo);

        if (caminho_log == NULL) {
            char detalhe[128];
            (void)snprintf(detalhe, sizeof(detalhe),
                           "falha de alocacao: %s", strerror(errno));
            if (registrar_falha(configuracao, raizes[i].caminho, detalhe,
                                &houve_falha) != 0)
                goto falha_auditoria;
            continue;
        }

        if (garantir_diretorio_destino(fd_destino, raizes[i].rotulo,
                                       &fd_raiz_destino) != 0) {
            char detalhe[128];
            (void)snprintf(detalhe, sizeof(detalhe),
                           "preparacao do destino da raiz: %s",
                           strerror(errno));
            if (registrar_falha(configuracao, raizes[i].caminho, detalhe,
                                &houve_falha) != 0) {
                free(caminho_log);
                goto falha_auditoria;
            }
            free(caminho_log);
            continue;
        }

        resultado_raiz = percorrer_diretorio(configuracao,
                                             raizes[i].caminho,
                                             caminho_log,
                                             fd_raiz_destino, fd_destino,
                                             &visitados, &houve_falha);
        if (close(fd_raiz_destino) != 0) {
            char detalhe[128];
            (void)snprintf(detalhe, sizeof(detalhe),
                           "close da raiz de destino: %s", strerror(errno));
            if (registrar_falha(configuracao, caminho_log, detalhe,
                                &houve_falha) != 0) {
                free(caminho_log);
                goto falha_auditoria;
            }
        }
        fd_raiz_destino = -1;
        free(caminho_log);

        if (resultado_raiz != 0)
            goto falha_auditoria;
    }

    for (i = 0; i < 4; ++i)
        free(caminhos_home[i]);
    free(visitados.itens);

    if (close(fd_destino) != 0) {
        char detalhe[128];
        (void)snprintf(detalhe, sizeof(detalhe), "close do destino: %s",
                       strerror(errno));
        houve_falha = 1;
        if (registrar_evento(configuracao, "falha", configuracao->destino,
                             detalhe) != 0)
            return -1;
    }

    if (registrar_evento(configuracao, "execucao_finalizada", "",
                         houve_falha ? "concluida com falhas" :
                                       "concluida sem falhas") != 0)
        return -1;
    return houve_falha ? 1 : 0;

falha_auditoria:
    if (fd_raiz_destino >= 0)
        (void)close(fd_raiz_destino);
    for (i = 0; i < 4; ++i)
        free(caminhos_home[i]);
    free(visitados.itens);
    if (fd_destino >= 0)
        (void)close(fd_destino);
    return -1;
}