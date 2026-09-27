#define _GNU_SOURCE
#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct target_file_list {
    char **paths;
    size_t count;
    size_t capacity;
    const char *const *exts;
    size_t ext_count;
    int failed;
};

static char *target_file_join(const char *dir, const char *name)
{
    size_t dir_len = strlen(dir);
    size_t name_len = strlen(name);
    int separator = dir_len != 0 && dir[dir_len - 1] != '/';

    if (dir_len > SIZE_MAX - name_len ||
        dir_len + name_len > SIZE_MAX - (size_t)separator - 1)
        return NULL;

    size_t length = dir_len + name_len + (size_t)separator;
    char *path = malloc(length + 1);
    if (path == NULL)
        return NULL;

    memcpy(path, dir, dir_len);
    if (separator)
        path[dir_len++] = '/';
    memcpy(path + dir_len, name, name_len + 1);
    return path;
}

static int target_file_has_suffix(const char *name,
                                  const char *const *exts,
                                  size_t ext_count)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < ext_count; ++i) {
        if (exts[i] == NULL)
            continue;
        size_t ext_len = strlen(exts[i]);
        if (name_len >= ext_len &&
            memcmp(name + name_len - ext_len, exts[i], ext_len) == 0)
            return 1;
    }
    return 0;
}

static int target_file_append(struct target_file_list *list, char *path)
{
    if (list->count > SIZE_MAX - 2) {
        free(path);
        list->failed = 1;
        return -1;
    }

    size_t needed = list->count + 2;
    if (needed > list->capacity) {
        size_t capacity = list->capacity ? list->capacity : 16;
        while (capacity < needed) {
            if (capacity > SIZE_MAX / 2) {
                capacity = needed;
                break;
            }
            capacity *= 2;
        }
        if (capacity > SIZE_MAX / sizeof(*list->paths)) {
            free(path);
            list->failed = 1;
            return -1;
        }
        char **paths = realloc(list->paths, capacity * sizeof(*paths));
        if (paths == NULL) {
            free(path);
            list->failed = 1;
            return -1;
        }
        list->paths = paths;
        list->capacity = capacity;
    }

    list->paths[list->count++] = path;
    list->paths[list->count] = NULL;
    return 0;
}

static void target_file_walk(const char *dir, struct target_file_list *list)
{
    if (list->failed)
        return;

    DIR *stream = opendir(dir);
    if (stream == NULL)
        return;

    struct dirent *entry;
    while (!list->failed && (entry = readdir(stream)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *path = target_file_join(dir, entry->d_name);
        if (path == NULL) {
            list->failed = 1;
            break;
        }

        struct stat st;
        if (lstat(path, &st) != 0) {
            free(path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            target_file_walk(path, list);
            free(path);
        } else {
            int regular = S_ISREG(st.st_mode);
            if (S_ISLNK(st.st_mode) && !regular &&
                stat(path, &st) == 0 && S_ISREG(st.st_mode))
                regular = 1;

            if (regular &&
                target_file_has_suffix(entry->d_name, list->exts,
                                       list->ext_count)) {
                if (target_file_append(list, path) != 0)
                    break;
            } else {
                free(path);
            }
        }
    }

    closedir(stream);
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

    struct target_file_list list = {
        .paths = NULL,
        .count = 0,
        .capacity = 0,
        .exts = exts,
        .ext_count = ext_count,
        .failed = 0
    };

    const char *home = getenv("HOME");
    for (size_t i = 0; i < dir_count && !list.failed; ++i) {
        if (dirs[i] == NULL)
            continue;

        const char *dir = dirs[i];
        char *expanded = NULL;
        if (dir[0] == '~' && home != NULL) {
            size_t home_len = strlen(home);
            size_t rest_len = strlen(dir + 1);
            if (home_len > SIZE_MAX - rest_len ||
                home_len + rest_len == SIZE_MAX) {
                list.failed = 1;
                break;
            }
            expanded = malloc(home_len + rest_len + 1);
            if (expanded == NULL) {
                list.failed = 1;
                break;
            }
            memcpy(expanded, home, home_len);
            memcpy(expanded + home_len, dir + 1, rest_len + 1);
            dir = expanded;
        }

        target_file_walk(dir, &list);
        free(expanded);
    }

    if (list.failed) {
        for (size_t i = 0; i < list.count; ++i)
            free(list.paths[i]);
        free(list.paths);
        return 0;
    }

    if (list.count == 0) {
        free(list.paths);
        return 0;
    }

    *out_paths = list.paths;
    return list.count;
}