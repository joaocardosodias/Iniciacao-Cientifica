#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <syslog.h>
#include <wchar.h>
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct notificacao_resultado {
    const char *diretorio;
    const char *raiz_autorizada;
    size_t arquivos_transformados;
};

static int caminho_absoluto_valido(const char *caminho)
{
    const char *parte;

    if (caminho == NULL || caminho[0] != '/') {
        return 0;
    }

    if (caminho[1] == '\0') {
        return 1;
    }

    if (caminho[1] == '/') {
        return 0;
    }

    parte = caminho + 1;
    for (;;) {
        const char *fim = strchr(parte, '/');
        size_t tamanho = fim != NULL ? (size_t)(fim - parte) : strlen(parte);

        if (tamanho == 0 ||
            (tamanho == 1 && parte[0] == '.') ||
            (tamanho == 2 && parte[0] == '.' && parte[1] == '.')) {
            return 0;
        }

        if (fim == NULL) {
            return 1;
        }

        parte = fim + 1;
        if (*parte == '\0' || *parte == '/') {
            return 0;
        }
    }
}

 
static int abrir_diretorio_autorizado(const char *raiz, const char *diretorio)
{
    size_t tamanho_raiz;
    const char *relativo;
    int fd;

    if (!caminho_absoluto_valido(raiz) ||
        !caminho_absoluto_valido(diretorio)) {
        errno = EINVAL;
        return -1;
    }

    tamanho_raiz = strlen(raiz);
    if (strcmp(raiz, "/") == 0) {
        relativo = diretorio + 1;
    } else {
        if (strncmp(raiz, diretorio, tamanho_raiz) != 0 ||
            (diretorio[tamanho_raiz] != '\0' &&
             diretorio[tamanho_raiz] != '/')) {
            errno = EACCES;
            return -1;
        }

        relativo = diretorio[tamanho_raiz] == '/'
                       ? diretorio + tamanho_raiz + 1
                       : diretorio + tamanho_raiz;
    }

    fd = open(raiz, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (fd < 0) {
        return -1;
    }

    while (*relativo != '\0') {
        const char *fim = strchr(relativo, '/');
        size_t tamanho = fim != NULL ? (size_t)(fim - relativo) : strlen(relativo);
        char *componente;
        int proximo;

        componente = malloc(tamanho + 1);
        if (componente == NULL) {
            int erro = errno;
            close(fd);
            errno = erro;
            return -1;
        }

        memcpy(componente, relativo, tamanho);
        componente[tamanho] = '\0';

        proximo = openat(fd, componente,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        free(componente);
        if (proximo < 0) {
            int erro = errno;
            close(fd);
            errno = erro;
            return -1;
        }

        close(fd);
        fd = proximo;
        relativo = fim != NULL ? fim + 1 : relativo + tamanho;
    }

    return fd;
}

 
int notificacoes_operacionais(const struct notificacao_resultado *resultados,
                              size_t quantidade)
{
    static const char nome_aviso[] = "#_STATUS_NOTICE_#.txt";
    static const char conteudo[] =
        "A transformação autorizada dos dados foi concluída.\n"
        "Para obter assistência, contate a equipe de suporte da NovaPay "
        "pelo canal seguro oficial.\n";
    int primeiro_erro = 0;
    size_t i;

    if (quantidade != 0 && resultados == NULL) {
        errno = EINVAL;
        return -1;
    }

    for (i = 0; i < quantidade; ++i) {
        int diretorio_fd;
        int arquivo_fd;
        int erro = 0;
        size_t escrito = 0;
        size_t tamanho_conteudo = sizeof(conteudo) - 1;

        if (resultados[i].arquivos_transformados == 0) {
            continue;
        }

        diretorio_fd = abrir_diretorio_autorizado(
            resultados[i].raiz_autorizada, resultados[i].diretorio);
        if (diretorio_fd < 0) {
            if (primeiro_erro == 0) {
                primeiro_erro = errno;
            }
            continue;
        }

        arquivo_fd = openat(diretorio_fd, nome_aviso,
                            O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW |
                                O_CLOEXEC,
                            0644);
        if (arquivo_fd < 0) {
            erro = errno;
        } else {
            while (escrito < tamanho_conteudo) {
                ssize_t quantidade_escrita =
                    write(arquivo_fd, conteudo + escrito,
                          tamanho_conteudo - escrito);

                if (quantidade_escrita < 0) {
                    if (errno == EINTR) {
                        continue;
                    }
                    erro = errno;
                    break;
                }

                if (quantidade_escrita == 0) {
                    erro = EIO;
                    break;
                }

                escrito += (size_t)quantidade_escrita;
            }

            if (erro == 0 && fsync(arquivo_fd) < 0) {
                erro = errno;
            }

            if (close(arquivo_fd) < 0 && erro == 0) {
                erro = errno;
            }

            if (erro == 0 && fsync(diretorio_fd) < 0) {
                erro = errno;
            }

            if (erro != 0) {
                unlinkat(diretorio_fd, nome_aviso, 0);
                fsync(diretorio_fd);
            }
        }

        if (close(diretorio_fd) < 0 && erro == 0) {
            erro = errno;
        }

        if (erro != 0 && primeiro_erro == 0) {
            primeiro_erro = erro;
        }
    }

    if (primeiro_erro != 0) {
        errno = primeiro_erro;
        return -1;
    }

    return 0;
}