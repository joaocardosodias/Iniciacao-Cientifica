#define _GNU_SOURCE
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>
#include <pwd.h>
#include <limits.h>

static char *expand_path(const char *path)
{
    if (!path)
        return NULL;
    if (path[0] != '~')
        return strdup(path);
    const char *home = getenv("HOME");
    if (!home) {
        struct passwd *pw = getpwuid(getuid());
        if (pw)
            home = pw->pw_dir;
    }
    if (!home)
        return strdup(path + 1); /* fallback: empty home */
    size_t home_len = strlen(home);
    size_t rest_len = strlen(path + 1);
    char *res = malloc(home_len + rest_len + 1);
    if (!res)
        return NULL;
    memcpy(res, home, home_len);
    memcpy(res + home_len, path + 1, rest_len + 1);
    return res;
}

static int has_extension(const char *filename, const char *const *exts, size_t ext_count)
{
    if (!filename || ext_count == 0)
        return 0;
    const char *base = strrchr(filename, '/');
    const char *name = base ? base + 1 : filename;
    size_t name_len = strlen(name);
    for (size_t i = 0; i < ext_count; ++i) {
        const char *ext = exts[i];
        size_t ext_len = strlen(ext);
        if (ext_len == 0)
            continue;
        if (ext_len > name_len)
            continue;
        if (strcmp(name + name_len - ext_len, ext) == 0)
            return 1;
    }
    return 0;
}

static int ensure_capacity(char ***list, size_t *cap, size_t needed)
{
    if (*cap >= needed)
        return 0;
    size_t new_cap = *cap ? *cap * 2 : 64;
    while (new_cap < needed)
        new_cap *= 2;
    char **tmp = realloc(*list, new_cap * sizeof(char *));
    if (!tmp)
        return -1;
    *list = tmp;
    *cap = new_cap;
    return 0;
}

static int walk_dir(const char *dir, const char *const *exts, size_t ext_count,
                    char ***list, size_t *list_cap, size_t *list_len)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0; /* skip unreadable directory */
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        size_t dir_len = strlen(dir);
        size_t name_len = strlen(entry->d_name);
        int need_slash = (dir_len > 0 && dir[dir_len - 1] != '/');
        size_t path_len = dir_len + need_slash + name_len + 1;
        char *full = malloc(path_len);
        if (!full) {
            closedir(d);
            return -1;
        }
        memcpy(full, dir, dir_len);
        if (need_slash)
            full[dir_len] = '/';
        memcpy(full + dir_len + need_slash, entry->d_name, name_len + 1);
        struct stat st;
        if (lstat(full, &st) == -1) {
            free(full);
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            if (walk_dir(full, exts, ext_count, list, list_cap, list_len) == -1) {
                free(full);
                closedir(d);
                return -1;
            }
        } else if (S_ISREG(st.st_mode)) {
            if (has_extension(full, exts, ext_count)) {
                if (ensure_capacity(list, list_cap, *list_len + 2) == -1) {
                    free(full);
                    closedir(d);
                    return -1;
                }
                (*list)[*list_len] = full;
                (*list_len)++;
                (*list)[*list_len] = NULL;
            } else {
                free(full);
            }
        } else {
            free(full);
        }
    }
    closedir(d);
    return 0;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (!out_paths) {
        errno = EINVAL;
        return 0;
    }
    *out_paths = NULL;
    char **list = NULL;
    size_t list_cap = 0;
    size_t list_len = 0;
    for (size_t i = 0; i < dir_count; ++i) {
        char *expanded = expand_path(dirs[i]);
        if (!expanded) {
            /* allocation failure */
            for (size_t j = 0; j < list_len; ++j)
                free(list[j]);
            free(list);
            return 0;
        }
        if (walk_dir(expanded, exts, ext_count, &list, &list_cap, &list_len) == -1) {
            free(expanded);
            for (size_t j = 0; j < list_len; ++j)
                free(list[j]);
            free(list);
            return 0;
        }
        free(expanded);
    }
    if (list_len == 0) {
        free(list);
        return 0;
    }
    /* Ensure NULL termination */
    if (ensure_capacity(&list, &list_cap, list_len + 1) == -1) {
        for (size_t j = 0; j < list_len; ++j)
            free(list[j]);
        free(list);
        return 0;
    }
    list[list_len] = NULL;
    *out_paths = list;
    return list_len;
}