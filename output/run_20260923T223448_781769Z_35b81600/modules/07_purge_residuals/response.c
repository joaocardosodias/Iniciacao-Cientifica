#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <unistd.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>
#include <ctype.h>

/* Verifica se o nome do arquivo possui uma das extensões alvo (case-insensitive) */
static int has_target_extension(const char *name) {
    const char *dot = strrchr(name, '.');
    if (!dot) return 0;
    const char *ext = dot + 1;
    if (strcasecmp(ext, "bak") == 0) return 1;
    if (strcasecmp(ext, "backup") == 0) return 1;
    if (strcasecmp(ext, "old") == 0) return 1;
    return 0;
}

/* Percorre recursivamente um diretório e deleta arquivos com extensões alvo */
static int purge_recursive(const char *dirpath, int *count, int debug) {
    DIR *dir = opendir(dirpath);
    if (!dir) {
        if (debug) fprintf(stderr, "purge: cannot open directory %s: %s\n", dirpath, strerror(errno));
        return -1; /* erro */
    }
    struct dirent *entry;
    char fullpath[PATH_MAX];
    struct stat st;
    int ret = 0;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        int len = snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, entry->d_name);
        if (len < 0 || (size_t)len >= sizeof(fullpath)) {
            if (debug) fprintf(stderr, "purge: path too long: %s/%s\n", dirpath, entry->d_name);
            ret = -1;
            continue;
        }
        if (lstat(fullpath, &st) != 0) {
            if (debug) fprintf(stderr, "purge: cannot stat %s: %s\n", fullpath, strerror(errno));
            ret = -1;
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            /* Subdiretório: recursão */
            if (purge_recursive(fullpath, count, debug) != 0)
                ret = -1;
        } else if (S_ISREG(st.st_mode)) {
            if (has_target_extension(entry->d_name)) {
                if (remove(fullpath) == 0) {
                    (*count)++;
                } else {
                    if (debug) fprintf(stderr, "purge: cannot remove %s: %s\n", fullpath, strerror(errno));
                    ret = -1;
                }
            }
        }
    }
    closedir(dir);
    return ret;
}

/* Expande '~' no início do caminho para o diretório home */
static int expand_path(const char *input, char *output, size_t outsize) {
    if (input[0] == '~' && (input[1] == '/' || input[1] == '\0')) {
        const char *home = getenv("HOME");
        if (!home) return -1;
        if (input[1] == '/')
            snprintf(output, outsize, "%s%s", home, input + 1);
        else
            snprintf(output, outsize, "%s", home);
    } else {
        snprintf(output, outsize, "%s", input);
    }
    return 0;
}

int purge_residuals(void) {
    const char *targets[] = {
        "~/Documentos_Teste",
        "~/Documentos",
        "~/Downloads",
        "~/Imagens",
        "/mnt"
    };
    int num_targets = sizeof(targets) / sizeof(targets[0]);

    int debug = 0;
    const char *env_debug = getenv("PURGE_DEBUG");
    if (env_debug && strcmp(env_debug, "1") == 0)
        debug = 1;

    int total_deleted = 0;
    char expanded_path[PATH_MAX];

    for (int i = 0; i < num_targets; i++) {
        if (expand_path(targets[i], expanded_path, sizeof(expanded_path)) != 0) {
            if (debug) fprintf(stderr, "purge: cannot expand path %s\n", targets[i]);
            continue;
        }
        struct stat st;
        if (stat(expanded_path, &st) != 0) {
            if (debug) fprintf(stderr, "purge: cannot access %s: %s\n", expanded_path, strerror(errno));
            continue;
        }
        if (!S_ISDIR(st.st_mode)) {
            if (debug) fprintf(stderr, "purge: %s is not a directory\n", expanded_path);
            continue;
        }
        purge_recursive(expanded_path, &total_deleted, debug);
    }
    return total_deleted;
}