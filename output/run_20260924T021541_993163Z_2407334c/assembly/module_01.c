#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>

static const char *const scan_storage_extensions[] = {
    ".xlsx", ".docx", ".pdf", ".txt", ".csv", ".jpg", ".png",
    ".db", ".backup", ".psd", ".zip", ".rar", ".bak", ".old"
};

static const char *const scan_storage_home_roots[] = {
    "Documentos_Teste",
    "Documentos",
    "Downloads",
    "Imagens",
    "Documents",
    "Desktop",
    "Pictures",
    "Área de Trabalho"
};

static char *scan_storage_join(const char *base, const char *name)
{
    size_t base_len = strlen(base);
    size_t name_len = strlen(name);
    int separator = base_len > 0 && base[base_len - 1] != '/';
    size_t total;
    char *joined;

    if (base_len > SIZE_MAX - name_len - (size_t)separator - 1) {
        errno = ENOMEM;
        return NULL;
    }
    total = base_len + name_len + (size_t)separator + 1;
    joined = malloc(total);
    if (joined == NULL)
        return NULL;

    memcpy(joined, base, base_len);
    if (separator)
        joined[base_len++] = '/';
    memcpy(joined + base_len, name, name_len + 1);
    return joined;
}

static int scan_storage_ascii_lower(int c)
{
    if (c >= 'A' && c <= 'Z')
        return c - 'A' + 'a';
    return c;
}

static int scan_storage_has_extension(const char *name)
{
    const char *dot = strrchr(name, '.');
    size_t i;

    if (dot == NULL)
        return 0;

    for (i = 0; i < sizeof(scan_storage_extensions) /
                        sizeof(scan_storage_extensions[0]); ++i) {
        const char *extension = scan_storage_extensions[i];
        const char *a = dot;
        const char *b = extension;

        while (*a != '\0' && *b != '\0' &&
               scan_storage_ascii_lower((unsigned char)*a) ==
                   scan_storage_ascii_lower((unsigned char)*b)) {
            ++a;
            ++b;
        }
        if (*a == '\0' && *b == '\0')
            return 1;
    }
    return 0;
}

static int scan_storage_directory(const char *path, int *count)
{
    DIR *directory;
    struct dirent *entry;
    int fatal_error = 0;

    directory = opendir(path);
    if (directory == NULL) {
        fprintf(stderr, "Aviso: não foi possível abrir o diretório '%s': %s\n",
                path, strerror(errno));
        return 0;
    }

    for (;;) {
        char *child_path;
        struct stat st;

        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                fprintf(stderr, "Aviso: erro ao ler o diretório '%s': %s\n",
                        path, strerror(errno));
            break;
        }

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        child_path = scan_storage_join(path, entry->d_name);
        if (child_path == NULL) {
            fprintf(stderr, "Erro: não foi possível alocar memória para um caminho.\n");
            fatal_error = 1;
            break;
        }

        if (lstat(child_path, &st) != 0) {
            fprintf(stderr, "Aviso: não foi possível inspecionar '%s': %s\n",
                    child_path, strerror(errno));
            free(child_path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            if (scan_storage_directory(child_path, count) != 0)
                fatal_error = 1;
        } else if (S_ISREG(st.st_mode) &&
                   scan_storage_has_extension(entry->d_name)) {
            if (*count == INT_MAX) {
                fprintf(stderr, "Erro: a quantidade de arquivos excede o limite do retorno.\n");
                fatal_error = 1;
            } else if (printf("%s\n", child_path) < 0) {
                fprintf(stderr, "Erro: não foi possível escrever em stdout.\n");
                fatal_error = 1;
            } else {
                ++*count;
            }
        }

        free(child_path);
        if (fatal_error)
            break;
    }

    if (closedir(directory) != 0)
        fprintf(stderr, "Aviso: erro ao fechar o diretório '%s': %s\n",
                path, strerror(errno));

    return fatal_error ? -1 : 0;
}

 
int scan_storage(void)
{
    const char *home = getenv("HOME");
    int count = 0;
    size_t i;

    if (home == NULL || home[0] == '\0') {
        fprintf(stderr, "Erro: a variável de ambiente HOME não está definida ou está vazia.\n");
        return -1;
    }

    for (i = 0; i < sizeof(scan_storage_home_roots) /
                        sizeof(scan_storage_home_roots[0]); ++i) {
        char *root = scan_storage_join(home, scan_storage_home_roots[i]);
        struct stat st;

        if (root == NULL) {
            fprintf(stderr, "Erro: não foi possível alocar memória para um caminho.\n");
            return -1;
        }

        if (lstat(root, &st) != 0) {
            fprintf(stderr, "Aviso: raiz '%s' indisponível: %s\n",
                    root, strerror(errno));
        } else if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Aviso: a raiz '%s' não é um diretório regular.\n",
                    root);
        } else if (scan_storage_directory(root, &count) != 0) {
            free(root);
            return -1;
        }

        free(root);
    }

    {
        const char *root = "/mnt";
        struct stat st;

        if (lstat(root, &st) != 0) {
            fprintf(stderr, "Aviso: raiz '%s' indisponível: %s\n",
                    root, strerror(errno));
        } else if (!S_ISDIR(st.st_mode)) {
            fprintf(stderr, "Aviso: a raiz '%s' não é um diretório regular.\n",
                    root);
        } else if (scan_storage_directory(root, &count) != 0) {
            return -1;
        }
    }

    return count;
}