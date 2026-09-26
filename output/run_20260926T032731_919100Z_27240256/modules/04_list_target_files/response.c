#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <unistd.h>
#include <errno.h>

static char *expand_path(const char *path)
{
    if (!path) return NULL;
    if (path[0] != '~')
        return strdup(path);
    const char *home = getenv("HOME");
    if (!home) home = "";
    size_t home_len = strlen(home);
    size_t rest_len = strlen(path + 1); // skip '~'
    char *res = malloc(home_len + rest_len + 1);
    if (!res) return NULL;
    memcpy(res, home, home_len);
    memcpy(res + home_len, path + 1, rest_len + 1);
    return res;
}

static int ends_with_any(const char *name, const char *const *exts, size_t ext_count)
{
    size_t name_len = strlen(name);
    for (size_t i = 0; i < ext_count; ++i) {
        const char *ext = exts[i];
        size_t ext_len = strlen(ext);
        if (ext_len > name_len) continue;
        if (strcmp(name + name_len - ext_len, ext) == 0)
            return 1;
    }
    return 0;
}

static int add_path(char ***paths, size_t *count, size_t *capacity, const char *path)
{
    if (*count + 1 >= *capacity) {
        size_t new_cap = (*capacity == 0) ? 64 : (*capacity * 2);
        char **tmp = realloc(*paths, new_cap * sizeof(char *));
        if (!tmp) return -1;
        *paths = tmp;
        *capacity = new_cap;
    }
    (*paths)[*count] = strdup(path);
    if (!(*paths)[*count]) return -1;
    (*count)++;
    return 0;
}

static void free_paths(char **paths, size_t count)
{
    for (size_t i = 0; i < count; ++i) {
        free(paths[i]);
    }
    free(paths);
}

static int walk_dir(const char *dir,
                    const char *const *exts, size_t ext_count,
                    char ***paths, size_t *count, size_t *capacity)
{
    DIR *d = opendir(dir);
    if (!d) return 0; // skip unreadable directory

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        size_t dir_len = strlen(dir);
        size_t name_len = strlen(entry->d_name);
        int need_slash = (dir_len == 0 || dir[dir_len - 1] != '/');
        size_t path_len = dir_len + (need_slash ? 1 : 0) + name_len;
        char *full_path = malloc(path_len + 1);
        if (!full_path) {
            closedir(d);
            return -1;
        }
        memcpy(full_path, dir, dir_len);
        if (need_slash) {
            full_path[dir_len] = '/';
            memcpy(full_path + dir_len + 1, entry->d_name, name_len + 1);
        } else {
            memcpy(full_path + dir_len, entry->d_name, name_len + 1);
        }

        struct stat st;
        if (lstat(full_path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                if (walk_dir(full_path, exts, ext_count, paths, count, capacity) != 0) {
                    free(full_path);
                    closedir(d);
                    return -1;
                }
            } else if (S_ISREG(st.st_mode)) {
                if (ends_with_any(entry->d_name, exts, ext_count)) {
                    if (add_path(paths, count, capacity, full_path) != 0) {
                        free(full_path);
                        closedir(d);
                        return -1;
                    }
                }
            }
        }
        free(full_path);
    }
    closedir(d);
    return 0;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (!out_paths) return 0;
    char **paths = NULL;
    size_t count = 0;
    size_t capacity = 0;

    for (size_t i = 0; i < dir_count; ++i) {
        char *expanded = expand_path(dirs[i]);
        if (!expanded) {
            free_paths(paths, count);
            *out_paths = NULL;
            return 0;
        }
        int res = walk_dir(expanded, exts, ext_count, &paths, &count, &capacity);
        free(expanded);
        if (res != 0) {
            free_paths(paths, count);
            *out_paths = NULL;
            return 0;
        }
    }

    if (count == 0) {
        *out_paths = NULL;
        return 0;
    }

    // NULL-terminate the array
    if (add_path(&paths, &count, &capacity, NULL) != 0) {
        free_paths(paths, count);
        *out_paths = NULL;
        return 0;
    }
    paths[count - 1] = NULL; // replace the last added NULL string with actual NULL

    *out_paths = paths;
    return count - 1; // number of valid paths
}