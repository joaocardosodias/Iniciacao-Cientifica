#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>
#include <limits.h>

static int has_extension(const char *name, const char *const *exts, size_t ext_count)
{
    size_t nlen = strlen(name);
    for (size_t i = 0; i < ext_count; i++) {
        size_t elen = strlen(exts[i]);
        if (elen == 0)
            continue;
        if (nlen >= elen && strcmp(name + nlen - elen, exts[i]) == 0)
            return 1;
    }
    return 0;
}

static int append_path(char ***arr, size_t *count, size_t *cap, const char *path)
{
    if (*count + 1 >= *cap) {
        size_t newcap = (*cap == 0) ? 16 : (*cap * 2);
        char **tmp = realloc(*arr, newcap * sizeof(char *));
        if (!tmp)
            return -1;
        *arr = tmp;
        *cap = newcap;
    }
    (*arr)[*count] = strdup(path);
    if (!(*arr)[*count])
        return -1;
    (*count)++;
    (*arr)[*count] = NULL;
    return 0;
}

static void walk_dir(const char *dirpath, const char *const *exts, size_t ext_count,
                     char ***arr, size_t *count, size_t *cap)
{
    DIR *d = opendir(dirpath);
    if (!d)
        return;

    struct dirent *ent;
    while ((ent = readdir(d)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        char fullpath[PATH_MAX];
        int n = snprintf(fullpath, sizeof(fullpath), "%s/%s", dirpath, ent->d_name);
        if (n < 0 || (size_t)n >= sizeof(fullpath))
            continue;

        struct stat st;
        if (lstat(fullpath, &st) != 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            walk_dir(fullpath, exts, ext_count, arr, count, cap);
        } else if (S_ISREG(st.st_mode)) {
            if (has_extension(ent->d_name, exts, ext_count)) {
                append_path(arr, count, cap, fullpath);
            }
        }
    }
    closedir(d);
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    *out_paths = NULL;

    char **arr = NULL;
    size_t count = 0;
    size_t cap = 0;

    const char *home = getenv("HOME");

    for (size_t i = 0; i < dir_count; i++) {
        const char *dir = dirs[i];
        char expanded[PATH_MAX];

        if (dir[0] == '~') {
            if (home) {
                int n = snprintf(expanded, sizeof(expanded), "%s%s", home, dir + 1);
                if (n < 0 || (size_t)n >= sizeof(expanded))
                    continue;
                dir = expanded;
            }
        }

        walk_dir(dir, exts, ext_count, &arr, &count, &cap);
    }

    if (count == 0) {
        free(arr);
        *out_paths = NULL;
        return 0;
    }

    *out_paths = arr;
    return count;
}