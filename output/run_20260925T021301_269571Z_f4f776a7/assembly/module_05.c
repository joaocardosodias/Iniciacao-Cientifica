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
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#define AVISO_STATUS "#_STATUS_NOTICE_#.txt"
#define TAMANHO_BLOCO 16384

struct contexto_notificacoes {
    int fd_registro;
    int houve_erro;
};

static int escrever_tudo(int fd, const void *dados, size_t tamanho)
{
    const unsigned char *p = dados;

    while (tamanho > 0) {
        ssize_t n = write(fd, p, tamanho);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        p += (size_t)n;
        tamanho -= (size_t)n;
    }

    return 0;
}

static int escrever_json_string(int fd, const char *texto)
{
    static const char hex[] = "0123456789abcdef";
    const unsigned char *p = (const unsigned char *)texto;

    if (escrever_tudo(fd, "\"", 1) < 0)
        return -1;

    while (*p != '\0') {
        char escapado[6];
        size_t tamanho;

        switch (*p) {
        case '"':
            memcpy(escapado, "\\\"", 2);
            tamanho = 2;
            break;
        case '\\':
            memcpy(escapado, "\\\\", 2);
            tamanho = 2;
            break;
        case '\b':
            memcpy(escapado, "\\b", 2);
            tamanho = 2;
            break;
        case '\f':
            memcpy(escapado, "\\f", 2);
            tamanho = 2;
            break;
        case '\n':
            memcpy(escapado, "\\n", 2);
            tamanho = 2;
            break;
        case '\r':
            memcpy(escapado, "\\r", 2);
            tamanho = 2;
            break;
        case '\t':
            memcpy(escapado, "\\t", 2);
            tamanho = 2;
            break;
        default:
            if (*p < 0x20 || *p >= 0x7f) {
                escapado[0] = '\\';
                escapado[1] = 'u';
                escapado[2] = '0';
                escapado[3] = '0';
                escapado[4] = hex[*p >> 4];
                escapado[5] = hex[*p & 0x0f];
                tamanho = 6;
            } else {
                escapado[0] = (char)*p;
                tamanho = 1;
            }
            break;
        }

        if (escrever_tudo(fd, escapado, tamanho) < 0)
            return -1;
        ++p;
    }

    return escrever_tudo(fd, "\"", 1);
}

static int escrever_prefixo_registro(int fd)
{
    struct timespec agora;
    struct tm utc;
    char marca_tempo[32];
    int n;

    if (clock_gettime(CLOCK_REALTIME, &agora) < 0)
        return -1;
    if (gmtime_r(&agora.tv_sec, &utc) == NULL) {
        errno = EOVERFLOW;
        return -1;
    }

    n = snprintf(marca_tempo, sizeof(marca_tempo),
                 "%04d-%02d-%02dT%02d:%02d:%02d.%09ldZ",
                 utc.tm_year + 1900, utc.tm_mon + 1, utc.tm_mday,
                 utc.tm_hour, utc.tm_min, utc.tm_sec, agora.tv_nsec);
    if (n < 0 || (size_t)n >= sizeof(marca_tempo)) {
        errno = EOVERFLOW;
        return -1;
    }

    if (escrever_tudo(fd, "{\"time\":", 8) < 0 ||
        escrever_json_string(fd, marca_tempo) < 0)
        return -1;

    return 0;
}

static int registrar_erro(struct contexto_notificacoes *ctx,
                          const char *caminho, int codigo_erro)
{
    char descricao[256];
    int n;

    ctx->houve_erro = 1;
    if (escrever_prefixo_registro(ctx->fd_registro) < 0)
        return -1;
    if (escrever_tudo(ctx->fd_registro, ",\"event\":\"error\",\"path\":", 25) < 0 ||
        escrever_json_string(ctx->fd_registro, caminho) < 0)
        return -1;

    n = snprintf(descricao, sizeof(descricao), "%s", strerror(codigo_erro));
    if (n < 0 || (size_t)n >= sizeof(descricao)) {
        errno = EOVERFLOW;
        return -1;
    }

    if (escrever_tudo(ctx->fd_registro, ",\"errno\":", 9) < 0)
        return -1;

    n = snprintf(descricao, sizeof(descricao), "%d", codigo_erro);
    if (n < 0 || (size_t)n >= sizeof(descricao))
        return -1;
    if (escrever_tudo(ctx->fd_registro, descricao, (size_t)n) < 0 ||
        escrever_tudo(ctx->fd_registro, ",\"message\":", 11) < 0)
        return -1;

    n = snprintf(descricao, sizeof(descricao), "%s", strerror(codigo_erro));
    if (n < 0 || (size_t)n >= sizeof(descricao))
        return -1;
    if (escrever_json_string(ctx->fd_registro, descricao) < 0 ||
        escrever_tudo(ctx->fd_registro, "}\n", 2) < 0)
        return -1;

    return 0;
}

static char *juntar_caminho(const char *diretorio, const char *nome)
{
    size_t nd = strlen(diretorio);
    size_t nn = strlen(nome);
    int separador = nd == 0 || diretorio[nd - 1] != '/';
    char *resultado;

    if (nd > SIZE_MAX - nn - (size_t)separador - 1) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    resultado = malloc(nd + nn + (size_t)separador + 1);
    if (resultado == NULL)
        return NULL;

    memcpy(resultado, diretorio, nd);
    if (separador)
        resultado[nd++] = '/';
    memcpy(resultado + nd, nome, nn);
    resultado[nd + nn] = '\0';
    return resultado;
}

static int nome_e_aviso(const char *nome)
{
    static const char *const marcadores[] = {
        "ransom",
        "decrypt",
        "extortion",
        "status_notice",
        "how_to_restore",
        "recover_files",
        "your_files",
        NULL
    };
    const char *const *marcador;

    if (strcmp(nome, AVISO_STATUS) == 0)
        return 1;

    for (marcador = marcadores; *marcador != NULL; ++marcador) {
        if (strcasestr(nome, *marcador) != NULL)
            return 1;
    }

    return 0;
}

static int registrar_aviso(struct contexto_notificacoes *ctx,
                           const char *caminho, const struct stat *st,
                           const char *estado_leitura)
{
    char numero[128];
    int n;

    if (escrever_prefixo_registro(ctx->fd_registro) < 0 ||
        escrever_tudo(ctx->fd_registro, ",\"event\":\"notice\",\"path\":", 26) < 0 ||
        escrever_json_string(ctx->fd_registro, caminho) < 0 ||
        escrever_tudo(ctx->fd_registro, ",\"read_status\":", 15) < 0 ||
        escrever_json_string(ctx->fd_registro, estado_leitura) < 0)
        return -1;

    n = snprintf(numero, sizeof(numero),
                 ",\"size\":%jd,\"mtime\":%jd,\"device\":%ju,\"inode\":%ju",
                 (intmax_t)st->st_size, (intmax_t)st->st_mtime,
                 (uintmax_t)st->st_dev, (uintmax_t)st->st_ino);
    if (n < 0 || (size_t)n >= sizeof(numero)) {
        errno = EOVERFLOW;
        return -1;
    }

    return escrever_tudo(ctx->fd_registro, numero, (size_t)n) < 0 ||
           escrever_tudo(ctx->fd_registro, "}\n", 2) < 0 ? -1 : 0;
}

static int registrar_evento_simples(struct contexto_notificacoes *ctx,
                                    const char *evento, const char *caminho)
{
    if (escrever_prefixo_registro(ctx->fd_registro) < 0 ||
        escrever_tudo(ctx->fd_registro, ",\"event\":", 9) < 0 ||
        escrever_json_string(ctx->fd_registro, evento) < 0 ||
        escrever_tudo(ctx->fd_registro, ",\"path\":", 8) < 0 ||
        escrever_json_string(ctx->fd_registro, caminho) < 0 ||
        escrever_tudo(ctx->fd_registro, "}\n", 2) < 0)
        return -1;

    return 0;
}

static int percorrer_diretorio(struct contexto_notificacoes *ctx, int fd_dir,
                               const char *caminho_dir)
{
    DIR *dir;
    struct dirent *entrada;
    int fd_propriedade = dup(fd_dir);

    if (fd_propriedade < 0)
        return registrar_erro(ctx, caminho_dir, errno) < 0 ? -1 : 0;

    dir = fdopendir(fd_propriedade);
    if (dir == NULL) {
        int erro = errno;
        close(fd_propriedade);
        return registrar_erro(ctx, caminho_dir, erro) < 0 ? -1 : 0;
    }

    for (;;) {
        struct stat st;
        char *caminho;
        int erro_entrada;

        errno = 0;
        entrada = readdir(dir);
        if (entrada == NULL) {
            erro_entrada = errno;
            if (erro_entrada != 0 &&
                registrar_erro(ctx, caminho_dir, erro_entrada) < 0) {
                closedir(dir);
                return -1;
            }
            break;
        }

        if (strcmp(entrada->d_name, ".") == 0 ||
            strcmp(entrada->d_name, "..") == 0)
            continue;

        caminho = juntar_caminho(caminho_dir, entrada->d_name);
        if (caminho == NULL) {
            int erro = errno;
            if (registrar_erro(ctx, caminho_dir, erro) < 0) {
                closedir(dir);
                return -1;
            }
            continue;
        }

        if (fstatat(fd_dir, entrada->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
            int erro = errno;
            if (registrar_erro(ctx, caminho, erro) < 0) {
                free(caminho);
                closedir(dir);
                return -1;
            }
            free(caminho);
            continue;
        }

        if (S_ISLNK(st.st_mode)) {
            if (registrar_evento_simples(ctx, "symlink_skipped", caminho) < 0) {
                free(caminho);
                closedir(dir);
                return -1;
            }
            free(caminho);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            int fd_filho = openat(fd_dir, entrada->d_name,
                                  O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (fd_filho < 0) {
                int erro = errno;
                if (registrar_erro(ctx, caminho, erro) < 0) {
                    free(caminho);
                    closedir(dir);
                    return -1;
                }
            } else {
                if (percorrer_diretorio(ctx, fd_filho, caminho) < 0) {
                    close(fd_filho);
                    free(caminho);
                    closedir(dir);
                    return -1;
                }
                close(fd_filho);
            }
            free(caminho);
            continue;
        }

        if (S_ISREG(st.st_mode) && nome_e_aviso(entrada->d_name)) {
            int fd_arquivo = openat(fd_dir, entrada->d_name,
                                    O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
            char estado_leitura[32] = "ok";
            int erro_leitura = 0;

            if (fd_arquivo < 0) {
                erro_leitura = errno;
                strcpy(estado_leitura, "failed");
            } else {
                unsigned char bloco[TAMANHO_BLOCO];

                for (;;) {
                    ssize_t lidos = read(fd_arquivo, bloco, sizeof(bloco));
                    if (lidos < 0) {
                        if (errno == EINTR)
                            continue;
                        erro_leitura = errno;
                        strcpy(estado_leitura, "failed");
                        break;
                    }
                    if (lidos == 0)
                        break;
                }

                if (close(fd_arquivo) < 0 && erro_leitura == 0) {
                    erro_leitura = errno;
                    strcpy(estado_leitura, "failed");
                }
            }

            if (registrar_aviso(ctx, caminho, &st, estado_leitura) < 0) {
                free(caminho);
                closedir(dir);
                return -1;
            }
            if (erro_leitura != 0 &&
                registrar_erro(ctx, caminho, erro_leitura) < 0) {
                free(caminho);
                closedir(dir);
                return -1;
            }
        }

        free(caminho);
    }

    if (closedir(dir) < 0) {
        int erro = errno;
        return registrar_erro(ctx, caminho_dir, erro) < 0 ? -1 : 0;
    }

    return 0;
}

int notificacoes_operacionais(const char *const diretorios[],
                               size_t quantidade,
                               const char *arquivo_registro)
{
    struct contexto_notificacoes ctx;
    size_t i;
    int flags = O_WRONLY | O_APPEND | O_CREAT | O_CLOEXEC | O_NOFOLLOW;

    if (diretorios == NULL || arquivo_registro == NULL || arquivo_registro[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    ctx.fd_registro = open(arquivo_registro, flags, 0600);
    if (ctx.fd_registro < 0)
        return -1;
    ctx.houve_erro = 0;

    for (i = 0; i < quantidade; ++i) {
        int fd_raiz;
        struct stat st;

        if (diretorios[i] == NULL || diretorios[i][0] == '\0') {
            if (registrar_erro(&ctx, "(diretorio_invalido)", EINVAL) < 0) {
                close(ctx.fd_registro);
                return -1;
            }
            continue;
        }

        fd_raiz = open(diretorios[i],
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (fd_raiz < 0) {
            int erro = errno;
            if (registrar_erro(&ctx, diretorios[i], erro) < 0) {
                close(ctx.fd_registro);
                return -1;
            }
            continue;
        }

        if (fstat(fd_raiz, &st) < 0) {
            int erro = errno;
            if (registrar_erro(&ctx, diretorios[i], erro) < 0) {
                close(fd_raiz);
                close(ctx.fd_registro);
                return -1;
            }
            close(fd_raiz);
            continue;
        }

        if (percorrer_diretorio(&ctx, fd_raiz, diretorios[i]) < 0) {
            close(fd_raiz);
            close(ctx.fd_registro);
            return -1;
        }

        close(fd_raiz);
    }

    if (close(ctx.fd_registro) < 0)
        return -1;

    return ctx.houve_erro ? -1 : 0;
}