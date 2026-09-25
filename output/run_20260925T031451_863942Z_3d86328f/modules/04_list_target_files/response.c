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
};

static int target_path_matches(const char *name, const char *const *exts,
                               size_t ext_count)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < ext_count; ++i) {
        if (exts == NULL || exts[i] == NULL)
            continue;

        size_t ext_len = strlen(exts[i]);
        if (ext_len <= name_len &&
            memcmp(name + name_len - ext_len, exts[i], ext_len) == 0)
            return 1;
    }

    return 0;
}

static char *target_join_path(const char *base, const char *name)
{
    size_t base_len = strlen(base);
    size_t name_len = strlen(name);
    int add_slash = base_len != 0 && base[base_len - 1] != '/';

    if (base_len > SIZE_MAX - name_len - (size_t)add_slash - 1)
        return NULL;

    size_t length = base_len + (size_t)add_slash + name_len + 1;
    char *path = malloc(length);
    if (path == NULL)
        return NULL;

    memcpy(path, base, base_len);
    size_t offset = base_len;
    if (add_slash)
        path[offset++] = '/';
    memcpy(path + offset, name, name_len + 1);
    return path;
}

static int target_file_list_append(struct target_file_list *list, char *path)
{
    if (list->count > SIZE_MAX - 2)
        return -1;

    size_t needed = list->count + 2;
    if (needed > list->capacity) {
        size_t capacity = list->capacity == 0 ? 16 : list->capacity;
        while (capacity < needed) {
            if (capacity > SIZE_MAX / 2) {
                capacity = needed;
                break;
            }
            capacity *= 2;
        }
        if (capacity > SIZE_MAX / sizeof(*list->paths))
            return -1;

        char **paths = realloc(list->paths, capacity * sizeof(*paths));
        if (paths == NULL)
            return -1;
        list->paths = paths;
        list->capacity = capacity;
    }

    list->paths[list->count++] = path;
    list->paths[list->count] = NULL;
    return 0;
}

static int target_walk_directory(const char *directory,
                                 const char *const *exts,
                                 size_t ext_count,
                                 struct target_file_list *list)
{
    DIR *dir = opendir(directory);
    if (dir == NULL)
        return 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *path = target_join_path(directory, entry->d_name);
        if (path == NULL) {
            closedir(dir);
            return -1;
        }

        struct stat st;
        if (lstat(path, &st) != 0) {
            free(path);
            continue;
        }

        if (S_ISREG(st.st_mode)) {
            if (target_path_matches(entry->d_name, exts, ext_count)) {
                if (target_file_list_append(list, path) != 0) {
                    free(path);
                    closedir(dir);
                    return -1;
                }
            } else {
                free(path);
            }
        } else if (S_ISDIR(st.st_mode)) {
            if (target_walk_directory(path, exts, ext_count, list) != 0) {
                free(path);
                closedir(dir);
                return -1;
            }
            free(path);
        } else {
            free(path);
        }
    }

    closedir(dir);
    return 0;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    struct target_file_list list = {0};

    for (size_t i = 0; i < dir_count; ++i) {
        if (dirs == NULL || dirs[i] == NULL)
            continue;

        const char *directory = dirs[i];
        char *expanded = NULL;

        if (directory[0] == '~' &&
            (directory[1] == '\0' || directory[1] == '/')) {
            const char *home = getenv("HOME");
            if (home == NULL)
                continue;

            size_t home_len = strlen(home);
            size_t suffix_len = strlen(directory + 1);
            if (home_len > SIZE_MAX - suffix_len - 1)
                goto error;

            expanded = malloc(home_len + suffix_len + 1);
            if (expanded == NULL)
                goto error;

            memcpy(expanded, home, home_len);
            memcpy(expanded + home_len, directory + 1, suffix_len + 1);
            directory = expanded;
        }

        int result = target_walk_directory(directory, exts, ext_count, &list);
        free(expanded);
        if (result != 0)
            goto error;
    }

    if (list.count == 0) {
        free(list.paths);
        return 0;
    }

    *out_paths = list.paths;
    return list.count;

error:
    for (size_t i = 0; i < list.count; ++i)
        free(list.paths[i]);
    free(list.paths);
    return 0;
}