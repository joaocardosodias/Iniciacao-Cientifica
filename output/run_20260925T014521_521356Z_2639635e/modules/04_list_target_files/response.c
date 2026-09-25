#define _GNU_SOURCE
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>
#include <errno.h>

static int path_ends_with(const char *str, const char *suffix)
{
    size_t slen = strlen(str);
    size_t suf_len = strlen(suffix);
    if (suf_len > slen)
        return 0;
    return strcmp(str + slen - suf_len, suffix) == 0;
}

static int has_extension(const char *name, const char *const *exts, size_t ext_count)
{
    for (size_t i = 0; i < ext_count; ++i) {
        if (path_ends_with(name, exts[i]))
            return 1;
    }
    return 0;
}

static int expand_home(const char *path, char **out_expanded)
{
    if (!path || path[0] != '~') {
        *out_expanded = strdup(path);
        return *out_expanded ? 0 : -1;
    }

    const char *home = getenv("HOME");
    if (!home)
        home = "";

    const char *rest = path + 1; /* skip '~' */
    if (*rest == '/' )
        ++rest; /* skip '/' */

    size_t home_len = strlen(home);
    size_t rest_len = strlen(rest);
    size_t total = home_len + (rest_len ? 1 + rest_len : 0) + 1;
    char *buf = (char *)malloc(total);
    if (!buf)
        return -1;

    if (rest_len) {
        memcpy(buf, home, home_len);
        buf[home_len] = '/';
        memcpy(buf + home_len + 1, rest, rest_len);
        buf[home_len + 1 + rest_len] = '\0';
    } else {
        memcpy(buf, home, home_len);
        buf[home_len] = '\0';
    }
    *out_expanded = buf;
    return 0;
}

struct collector {
    char **paths;
    size_t count;
    size_t capacity;
};

static int collector_add(struct collector *c, const char *path)
{
    if (c->count + 1 >= c->capacity) {
        size_t new_cap = c->capacity ? c->capacity * 2 : 64;
        char **tmp = (char **)realloc(c->paths, new_cap * sizeof(char *));
        if (!tmp)
            return -1;
        c->paths = tmp;
        c->capacity = new_cap;
    }
    c->paths[c->count] = strdup(path);
    if (!c->paths[c->count])
        return -1;
    c->count++;
    return 0;
}

static void collector_finalize(struct collector *c)
{
    if (c->paths) {
        if (c->count >= c->capacity) {
            c->paths = (char **)realloc(c->paths, (c->capacity + 1) * sizeof(char *));
        }
        c->paths[c->count] = NULL;
    }
}

static int recurse_dir(const char *dir,
                       const char *const *exts,
                       size_t ext_count,
                       struct collector *c)
{
    DIR *dp = opendir(dir);
    if (!dp)
        return 0; /* skip unreadable directories */

    struct dirent *entry;
    while ((entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        size_t dir_len = strlen(dir);
        size_t name_len = strlen(entry->d_name);
        int need_slash = (dir_len && dir[dir_len - 1] != '/');
        size_t path_len = dir_len + (need_slash ? 1 : 0) + name_len + 1;
        char *full_path = (char *)malloc(path_len);
        if (!full_path) {
            closedir(dp);
            return -1;
        }

        memcpy(full_path, dir, dir_len);
        if (need_slash) {
            full_path[dir_len] = '/';
            memcpy(full_path + dir_len + 1, entry->d_name, name_len);
            full_path[dir_len + 1 + name_len] = '\0';
        } else {
            memcpy(full_path + dir_len, entry->d_name, name_len);
            full_path[dir_len + name_len] = '\0';
        }

        struct stat st;
        if (lstat(full_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                if (recurse_dir(full_path, exts, ext_count, c) < 0) {
                    free(full_path);
                    closedir(dp);
                    return -1;
                }
            } else if (S_ISREG(st.st_mode)) {
                if (ext_count == 0 || has_extension(entry->d_name, exts, ext_count)) {
                    if (collector_add(c, full_path) < 0) {
                        free(full_path);
                        closedir(dp);
                        return -1;
                    }
                }
            }
        }
        free(full_path);
    }
    closedir(dp);
    return 0;
}

size_t list_target_files(const char *const *dirs,
                         size_t dir_count,
                         const char *const *exts,
                         size_t ext_count,
                         char ***out_paths)
{
    if (!out_paths) {
        return 0;
    }
    *out_paths = NULL;

    if (dir_count == 0 || (ext_count == 0 && exts))
        return 0;

    struct collector col = {0};

    for (size_t i = 0; i < dir_count; ++i) {
        char *expanded = NULL;
        if (expand_home(dirs[i], &expanded) < 0) {
            /* memory error, abort */
            for (size_t j = 0; j < col.count; ++j)
                free(col.paths[j]);
            free(col.paths);
            return 0;
        }

        if (recurse_dir(expanded, exts, ext_count, &col) < 0) {
            free(expanded);
            for (size_t j = 0; j < col.count; ++j)
                free(col.paths[j]);
            free(col.paths);
            return 0;
        }
        free(expanded);
    }

    if (col.count == 0) {
        return 0;
    }

    collector_finalize(&col);
    *out_paths = col.paths;
    return col.count;
}