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

static char *target_child_path(const char *parent, const char *name)
{
    size_t parent_len = strlen(parent);
    size_t name_len = strlen(name);
    int needs_slash = parent_len != 0 && parent[parent_len - 1] != '/';

    if (parent_len > SIZE_MAX - name_len - (size_t)needs_slash - 1)
        return NULL;

    size_t length = parent_len + name_len + (size_t)needs_slash;
    char *path = malloc(length + 1);
    if (path == NULL)
        return NULL;

    memcpy(path, parent, parent_len);
    if (needs_slash)
        path[parent_len++] = '/';
    memcpy(path + parent_len, name, name_len + 1);
    return path;
}

static int target_has_extension(const char *name,
                                const char *const *exts,
                                size_t ext_count)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < ext_count; ++i) {
        const char *ext = exts[i];
        if (ext == NULL)
            continue;

        size_t ext_len = strlen(ext);
        if (name_len >= ext_len &&
            memcmp(name + name_len - ext_len, ext, ext_len) == 0)
            return 1;
    }
    return 0;
}

static int target_append_path(struct target_file_list *list, char *path)
{
    if (list->count == list->capacity) {
        size_t max_capacity = SIZE_MAX / sizeof(*list->paths) - 1;
        if (list->capacity >= max_capacity)
            return -1;

        size_t new_capacity;
        if (list->capacity == 0) {
            new_capacity = 16;
        } else if (list->capacity > max_capacity / 2) {
            new_capacity = max_capacity;
        } else {
            new_capacity = list->capacity * 2;
        }

        if (new_capacity > max_capacity)
            new_capacity = max_capacity;

        char **new_paths =
            realloc(list->paths, (new_capacity + 1) * sizeof(*list->paths));
        if (new_paths == NULL)
            return -1;

        list->paths = new_paths;
        list->capacity = new_capacity;
    }

    list->paths[list->count++] = path;
    list->paths[list->count] = NULL;
    return 0;
}

static void target_walk_directory(struct target_file_list *list,
                                  const char *directory)
{
    if (list->failed)
        return;

    DIR *dir = opendir(directory);
    if (dir == NULL)
        return;

    struct dirent *entry;
    while (!list->failed && (entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *path = target_child_path(directory, entry->d_name);
        if (path == NULL) {
            list->failed = 1;
            break;
        }

        struct stat st;
        if (lstat(path, &st) != 0) {
            free(path);
            continue;
        }

        if (S_ISREG(st.st_mode)) {
            if (target_has_extension(entry->d_name, list->exts,
                                     list->ext_count)) {
                if (target_append_path(list, path) != 0) {
                    free(path);
                    list->failed = 1;
                }
            } else {
                free(path);
            }
        } else if (S_ISDIR(st.st_mode)) {
            target_walk_directory(list, path);
            free(path);
        } else {
            free(path);
        }
    }

    closedir(dir);
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (out_paths == NULL)
        return 0;

    *out_paths = NULL;

    struct target_file_list list = {
        .paths = NULL,
        .count = 0,
        .capacity = 0,
        .exts = exts,
        .ext_count = exts == NULL ? 0 : ext_count,
        .failed = 0
    };

    if (dirs != NULL) {
        for (size_t i = 0; i < dir_count && !list.failed; ++i) {
            if (dirs[i] == NULL)
                continue;

            const char *directory = dirs[i];
            char *expanded = NULL;

            if (directory[0] == '~') {
                const char *home = getenv("HOME");
                if (home == NULL)
                    continue;

                size_t home_len = strlen(home);
                size_t suffix_len = strlen(directory + 1);
                if (home_len > SIZE_MAX - suffix_len - 1) {
                    list.failed = 1;
                    break;
                }

                expanded = malloc(home_len + suffix_len + 1);
                if (expanded == NULL) {
                    list.failed = 1;
                    break;
                }

                memcpy(expanded, home, home_len);
                memcpy(expanded + home_len, directory + 1, suffix_len + 1);
                directory = expanded;
            }

            target_walk_directory(&list, directory);
            free(expanded);
        }
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