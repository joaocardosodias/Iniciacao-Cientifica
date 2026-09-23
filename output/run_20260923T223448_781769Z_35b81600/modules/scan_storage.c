#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <ctype.h>
#include <limits.h>

/* Lista de extensões permitidas (em minúsculo) */
static const char *allowed_ext[] = {
    ".xlsx", ".docx", ".pdf", ".txt", ".csv",
    ".jpg", ".png", ".db", ".backup", ".psd",
    ".zip", ".rar", NULL
};

/* Verifica se o nome do arquivo termina com uma das extensões permitidas (case‑insensitive) */
static int has_allowed_extension(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot) return 0;
    size_t len_name = strlen(name);
    size_t len_ext = strlen(dot);
    /* Compara case‑insensitive com cada extensão */
    for (int i = 0; allowed_ext[i]; i++) {
        size_t ext_len = strlen(allowed_ext[i]);
        if (len_ext != ext_len) continue;
        /* Compara do final do nome até antes do ponto */
        int match = 1;
        for (size_t j = 0; j < ext_len; j++) {
            if (tolower((unsigned char)dot[j]) != tolower((unsigned char)allowed_ext[i][j])) {
                match = 0;
                break;
            }
        }
        if (match) return 1;
    }
    return 0;
}

/* Expande '~' no início do caminho para o valor de $HOME */
static char *expand_tilde(const char *path) {
    if (!path) return NULL;
    if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {
        const char *home = getenv("HOME");
        if (!home) {
            fprintf(stderr, "Erro: variável HOME não definida\n");
            return NULL;
        }
        size_t home_len = strlen(home);
        size_t path_len = strlen(path) + 1; /* inclui o '/' após ~ */
        char *result = malloc(home_len + path_len);
        if (!result) {
            perror("malloc");
            return NULL;
        }
        strcpy(result, home);
        /* Se path tem / depois de ~, copia a partir de path+1 (pula ~) */
        if (path[1] == '/')
            strcat(result, path + 1);
        else /* path é exatamente "~" */
            strcat(result, "");
        return result;
    }
    /* Se não começa com ~, retorna cópia */
    return strdup(path);
}

/* Adiciona o caminho 'path' à lista dinâmica de strings */
static int add_path(char ***list, int *count, int *capacity, const char *path) {
    if (*count >= *capacity) {
        int new_cap = *capacity ? *capacity * 2 : 64;
        char **tmp = realloc(*list, new_cap * sizeof(char *));
        if (!tmp) {
            perror("realloc");
            return -1;
        }
        *list = tmp;
        *capacity = new_cap;
    }
    (*list)[*count] = strdup(path);
    if (!(*list)[*count]) {
        perror("strdup");
        return -1;
    }
    (*count)++;
    return 0;
}

/* Função recursiva que percorre o diretório 'dir_path' e coleta arquivos com extensões permitidas */
static int crawl_directory(const char *dir_path, char ***list, int *count, int *capacity) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        /* Se não pode abrir (não existe, permissão), simplesmente ignora */
        return 0;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        /* Ignora . e .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        /* Constrói caminho completo para o item */
        size_t dir_len = strlen(dir_path);
        size_t name_len = strlen(entry->d_name);
        char *full_path = malloc(dir_len + 1 + name_len + 1);
        if (!full_path) {
            perror("malloc");
            closedir(dir);
            return -1;
        }
        strcpy(full_path, dir_path);
        if (full_path[dir_len - 1] != '/') {
            strcat(full_path, "/");
        }
        strcat(full_path, entry->d_name);

        /* Usa lstat para evitar loops com links simbólicos */
        struct stat st;
        if (lstat(full_path, &st) != 0) {
            free(full_path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            /* É um diretório (não link simbólico, pois lstat) – recursa */
            int ret = crawl_directory(full_path, list, count, capacity);
            if (ret != 0) {
                free(full_path);
                closedir(dir);
                return ret;
            }
        } else if (S_ISREG(st.st_mode)) {
            /* Arquivo regular – verifica extensão */
            if (has_allowed_extension(entry->d_name)) {
                if (add_path(list, count, capacity, full_path) != 0) {
                    free(full_path);
                    closedir(dir);
                    return -1;
                }
            }
        }

        free(full_path);
    }

    closedir(dir);
    return 0;
}

char **scan_storage(int *count) {
    if (!count) return NULL;
    *count = 0;

    /* Lista de diretórios base a percorrer (com ~ para expansão) */
    const char *base_dirs[] = {
        "~/Documentos_Teste",
        "~/Documentos",
        "~/Downloads",
        "~/Imagens",
        "/mnt",
        NULL
    };

    char **result = NULL;
    int capacity = 0;

    for (int i = 0; base_dirs[i]; i++) {
        char *expanded = expand_tilde(base_dirs[i]);
        if (!expanded) continue; /* erro já reportado */
        int ret = crawl_directory(expanded, &result, count, &capacity);
        free(expanded);
        if (ret != 0) {
            /* Em caso de erro, libera o que já foi alocado e retorna NULL */
            if (result) {
                for (int j = 0; j < *count; j++) free(result[j]);
                free(result);
            }
            *count = 0;
            return NULL;
        }
    }

    return result;
}