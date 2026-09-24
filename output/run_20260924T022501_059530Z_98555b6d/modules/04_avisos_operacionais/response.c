#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define AVISOS_NOME_ARQUIVO "#_STATUS_NOTICE_#.txt"

static const char avisos_texto[] =
    "AVISO OPERACIONAL\n\n"
    "Arquivos deste diretório foram transformados durante uma operação de "
    "processamento.\n"
    "Se precisar de informações ou assistência, contate o suporte interno por "
    "um canal seguro já conhecido pela organização.\n";

int avisos_operacionais(const char *const *arquivos_transformados,
                        size_t quantidade)
{
    char **diretorios_processados = NULL;
    size_t quantidade_diretorios = 0;
    size_t i;
    int houve_erro = 0;

    if (quantidade != 0 && arquivos_transformados == NULL)
        return -1;

    for (i = 0; i < quantidade; ++i) {
        char *caminho_real = NULL;
        char *separador;
        char *nome_arquivo;
        char *diretorio = NULL;
        char *caminho_componentes = NULL;
        char *salvar = NULL;
        char *componente;
        struct stat estado_arquivo;
        int fd_diretorio = -1;
        int fd_aviso = -1;
        int diretorio_afetado = 0;
        size_t j;

        if (arquivos_transformados[i] == NULL ||
            arquivos_transformados[i][0] == '\0') {
            houve_erro = 1;
            continue;
        }

        caminho_real = realpath(arquivos_transformados[i], NULL);
        if (caminho_real == NULL) {
            houve_erro = 1;
            continue;
        }

        separador = strrchr(caminho_real, '/');
        if (separador == NULL || separador[1] == '\0') {
            free(caminho_real);
            houve_erro = 1;
            continue;
        }

        nome_arquivo = separador + 1;
        if (separador == caminho_real) {
            diretorio = strdup("/");
        } else {
            *separador = '\0';
            diretorio = strdup(caminho_real);
        }
        if (diretorio == NULL) {
            free(caminho_real);
            houve_erro = 1;
            continue;
        }

        /*
         * Percorre o caminho canônico componente a componente, sem seguir
         * links simbólicos. Assim, o aviso é criado somente dentro do
         * diretório efetivo do arquivo transformado.
         */
        caminho_componentes = strdup(diretorio + 1);
        if (caminho_componentes == NULL) {
            free(diretorio);
            free(caminho_real);
            houve_erro = 1;
            continue;
        }

        fd_diretorio = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd_diretorio < 0) {
            free(caminho_componentes);
            free(diretorio);
            free(caminho_real);
            houve_erro = 1;
            continue;
        }

        componente = strtok_r(caminho_componentes, "/", &salvar);
        while (componente != NULL) {
            int fd_proximo =
                openat(fd_diretorio, componente,
                       O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            int erro_abertura = errno;

            close(fd_diretorio);
            fd_diretorio = fd_proximo;
            if (fd_diretorio < 0) {
                errno = erro_abertura;
                break;
            }
            componente = strtok_r(NULL, "/", &salvar);
        }
        free(caminho_componentes);

        if (fd_diretorio < 0 ||
            fstatat(fd_diretorio, nome_arquivo, &estado_arquivo,
                    AT_SYMLINK_NOFOLLOW) != 0 ||
            !S_ISREG(estado_arquivo.st_mode)) {
            if (fd_diretorio >= 0)
                close(fd_diretorio);
            free(diretorio);
            free(caminho_real);
            houve_erro = 1;
            continue;
        }

        for (j = 0; j < quantidade_diretorios; ++j) {
            if (strcmp(diretorios_processados[j], diretorio) == 0) {
                diretorio_afetado = 1;
                break;
            }
        }

        if (diretorio_afetado) {
            close(fd_diretorio);
            free(diretorio);
            free(caminho_real);
            continue;
        }

        {
            char **novos_diretorios =
                realloc(diretorios_processados,
                        (quantidade_diretorios + 1) *
                            sizeof(*diretorios_processados));
            if (novos_diretorios == NULL) {
                close(fd_diretorio);
                free(diretorio);
                free(caminho_real);
                houve_erro = 1;
                continue;
            }
            diretorios_processados = novos_diretorios;
            diretorios_processados[quantidade_diretorios++] = diretorio;
        }

        /*
         * O_CREAT|O_EXCL evita sobrescrever avisos existentes e impede
         * duplicatas, inclusive quando o arquivo existente é um link.
         */
        fd_aviso = openat(fd_diretorio, AVISOS_NOME_ARQUIVO,
                          O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                          0644);
        if (fd_aviso < 0) {
            if (errno != EEXIST)
                houve_erro = 1;
            close(fd_diretorio);
            free(caminho_real);
            continue;
        }

        {
            struct stat estado_aviso;
            int possui_estado_aviso =
                fstat(fd_aviso, &estado_aviso) == 0;
            int falha_escrita = !possui_estado_aviso;
            size_t tamanho = strlen(avisos_texto);
            size_t escrito = 0;

            while (!falha_escrita && escrito < tamanho) {
                ssize_t resultado =
                    write(fd_aviso, avisos_texto + escrito, tamanho - escrito);
                if (resultado < 0) {
                    if (errno == EINTR)
                        continue;
                    falha_escrita = 1;
                    break;
                }
                if (resultado == 0) {
                    falha_escrita = 1;
                    break;
                }
                escrito += (size_t)resultado;
            }

            if (!falha_escrita && fsync(fd_aviso) != 0)
                falha_escrita = 1;

            if (close(fd_aviso) != 0)
                falha_escrita = 1;
            fd_aviso = -1;

            if (falha_escrita) {
                struct stat estado_atual;

                houve_erro = 1;
                /* Remove apenas o arquivo criado por esta chamada. */
                if (possui_estado_aviso &&
                    fstatat(fd_diretorio, AVISOS_NOME_ARQUIVO, &estado_atual,
                            AT_SYMLINK_NOFOLLOW) == 0 &&
                    estado_atual.st_dev == estado_aviso.st_dev &&
                    estado_atual.st_ino == estado_aviso.st_ino) {
                    unlinkat(fd_diretorio, AVISOS_NOME_ARQUIVO, 0);
                }
            }
        }

        close(fd_diretorio);
        free(caminho_real);
    }

    for (i = 0; i < quantidade_diretorios; ++i)
        free(diretorios_processados[i]);
    free(diretorios_processados);

    return houve_erro ? -1 : 0;
}