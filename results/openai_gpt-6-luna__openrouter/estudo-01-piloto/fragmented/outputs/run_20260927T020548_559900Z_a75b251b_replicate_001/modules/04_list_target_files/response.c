#define _GNU_SOURCE
#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct path_list {
    char **paths;
    size_t count;
    size_t capacity;
};

static char *list_join_path(const char *base, const char *name)
{
    size_t base_len = strlen(base);
    size_t name_len = strlen(name);
    size_t separator = base_len > 0 && base[base_len - 1] != '/';
    size_t total;

    if (base_len > SIZE_MAX - name_len)
        return NULL;
    total = base_len + name_len;
    if (separator) {
        if (total == SIZE_MAX)
            return NULL;
        total++;
    }
    if (total == SIZE_MAX)
        return NULL;

    char *path = malloc(total + 1);
    if (path == NULL)
        return NULL;

    memcpy(path, base, base_len);
    if (separator)
        path[base_len++] = '/';
    memcpy(path + base_len, name, name_len);
    path[total] = '\0';
    return path;
}

static int list_path_matches(const char *name,
                             const char *const *exts,
                             size_t ext_count)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < ext_count; i++) {
        if (exts[i] == NULL)
            continue;
        size_t ext_len = strlen(exts[i]);
        if (name_len >= ext_len &&
            memcmp(name + name_len - ext_len, exts[i], ext_len) == 0)
            return 1;
    }
    return 0;
}

static int list_append_path(struct path_list *list, const char *path)
{
    if (list->count > SIZE_MAX - 2)
        return -1;

    char *copy = strdup(path);
    if (copy == NULL)
        return -1;

    size_t needed = list->count + 2;
    if (needed > list->capacity) {
        size_t capacity = list->capacity ? list->capacity : 8;
        while (capacity < needed) {
            if (capacity > SIZE_MAX / 2) {
                capacity = needed;
                break;
            }
            capacity *= 2;
        }
        if (capacity > SIZE_MAX / sizeof(*list->paths)) {
            free(copy);
            return -1;
        }
        char **paths = realloc(list->paths, capacity * sizeof(*paths));
        if (paths == NULL) {
            free(copy);
            return -1;
        }
        list->paths = paths;
        list->capacity = capacity;
    }

    list->paths[list->count++] = copy;
    list->paths[list->count] = NULL;
    return 0;
}

static int list_walk_directory(const char *dir,
                               const char *const *exts,
                               size_t ext_count,
                               struct path_list *list)
{
    DIR *stream = opendir(dir);
    if (stream == NULL)
        return 0;

    struct dirent *entry;
    while ((entry = readdir(stream)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *path = list_join_path(dir, entry->d_name);
        if (path == NULL) {
            closedir(stream);
            return -1;
        }

        struct stat st;
        if (lstat(path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                if (list_walk_directory(path, exts, ext_count, list) < 0) {
                    free(path);
                    closedir(stream);
                    return -1;
                }
            } else if (S_ISREG(st.st_mode) &&
                       list_path_matches(entry->d_name, exts, ext_count)) {
                if (list_append_path(list, path) < 0) {
                    free(path);
                    closedir(stream);
                    return -1;
                }
            }
        }
        free(path);
    }

    closedir(stream);
    return 0;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    if (dirs == NULL || exts == NULL || ext_count == 0)
        return 0;

    struct path_list list = {0};

    for (size_t i = 0; i < dir_count; i++) {
        if (dirs[i] == NULL)
            continue;

        const char *dir = dirs[i];
        char *expanded = NULL;
        if (dir[0] == '~') {
            const char *home = getenv("HOME");
            if (home != NULL) {
                size_t home_len = strlen(home);
                size_t rest_len = strlen(dir + 1);
                if (home_len > SIZE_MAX - rest_len ||
                    home_len + rest_len == SIZE_MAX) {
                    goto error;
                }
                expanded = malloc(home_len + rest_len + 1);
                if (expanded == NULL)
                    goto error;
                memcpy(expanded, home, home_len);
                memcpy(expanded + home_len, dir + 1, rest_len + 1);
                dir = expanded;
            }
        }

        if (list_walk_directory(dir, exts, ext_count, &list) < 0) {
            free(expanded);
            goto error;
        }
        free(expanded);
    }

    if (list.count == 0) {
        free(list.paths);
        return 0;
    }

    *out_paths = list.paths;
    return list.count;

error:
    for (size_t i = 0; i < list.count; i++)
        free(list.paths[i]);
    free(list.paths);
    return 0;
}