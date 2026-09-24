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

static int target_file_matches(const char *path, const char *const *exts,
                               size_t ext_count)
{
    size_t path_len = strlen(path);

    for (size_t i = 0; i < ext_count; ++i) {
        if (exts[i] == NULL)
            continue;
        size_t ext_len = strlen(exts[i]);
        if (ext_len <= path_len &&
            memcmp(path + path_len - ext_len, exts[i], ext_len) == 0)
            return 1;
    }
    return 0;
}

static int target_file_add(struct target_file_list *list, const char *path)
{
    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity ? list->capacity * 2 : 16;
        if (new_capacity < list->capacity ||
            new_capacity > SIZE_MAX / sizeof(*list->paths))
            return -1;
        char **new_paths = realloc(list->paths,
                                   new_capacity * sizeof(*list->paths));
        if (new_paths == NULL)
            return -1;
        list->paths = new_paths;
        list->capacity = new_capacity;
    }

    size_t length = strlen(path);
    if (length == SIZE_MAX)
        return -1;
    char *copy = malloc(length + 1);
    if (copy == NULL)
        return -1;
    memcpy(copy, path, length + 1);
    list->paths[list->count++] = copy;
    return 0;
}

static char *target_file_join(const char *directory, const char *name)
{
    size_t directory_len = strlen(directory);
    size_t name_len = strlen(name);
    int add_slash = directory_len == 0 || directory[directory_len - 1] != '/';

    if (directory_len > SIZE_MAX - name_len - (size_t)add_slash - 1)
        return NULL;

    size_t length = directory_len + name_len + (size_t)add_slash;
    char *path = malloc(length + 1);
    if (path == NULL)
        return NULL;

    memcpy(path, directory, directory_len);
    if (add_slash)
        path[directory_len++] = '/';
    memcpy(path + directory_len, name, name_len);
    path[length] = '\0';
    return path;
}

static int target_file_walk(const char *path, const char *const *exts,
                            size_t ext_count, struct target_file_list *list)
{
    struct stat st;
    if (lstat(path, &st) != 0)
        return 0;

    if (S_ISREG(st.st_mode))
        return target_file_matches(path, exts, ext_count)
                   ? target_file_add(list, path)
                   : 0;

    if (!S_ISDIR(st.st_mode))
        return 0;

    DIR *directory = opendir(path);
    if (directory == NULL)
        return 0;

    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *child = target_file_join(path, entry->d_name);
        if (child == NULL) {
            closedir(directory);
            return -1;
        }

        int result = target_file_walk(child, exts, ext_count, list);
        free(child);
        if (result != 0) {
            closedir(directory);
            return -1;
        }
    }

    closedir(directory);
    return 0;
}

static char *target_file_expand_home(const char *path)
{
    if (path[0] != '~')
        return strdup(path);

    const char *home = getenv("HOME");
    if (home == NULL)
        return strdup(path);

    size_t home_len = strlen(home);
    size_t suffix_len = strlen(path + 1);
    if (home_len > SIZE_MAX - suffix_len - 1)
        return NULL;

    char *expanded = malloc(home_len + suffix_len + 1);
    if (expanded == NULL)
        return NULL;
    memcpy(expanded, home, home_len);
    memcpy(expanded + home_len, path + 1, suffix_len + 1);
    return expanded;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (out_paths == NULL)
        return SIZE_MAX;
    *out_paths = NULL;

    if ((dir_count != 0 && dirs == NULL) ||
        (ext_count != 0 && exts == NULL))
        return SIZE_MAX;

    struct target_file_list list = {0};

    for (size_t i = 0; i < dir_count; ++i) {
        if (dirs[i] == NULL)
            continue;

        char *directory = target_file_expand_home(dirs[i]);
        if (directory == NULL)
            goto error;

        int result = target_file_walk(directory, exts, ext_count, &list);
        free(directory);
        if (result != 0)
            goto error;
    }

    if (list.count == 0) {
        free(list.paths);
        return 0;
    }

    if (list.count == SIZE_MAX ||
        list.count + 1 > SIZE_MAX / sizeof(*list.paths))
        goto error;

    char **result_paths = malloc((list.count + 1) * sizeof(*result_paths));
    if (result_paths == NULL)
        goto error;

    memcpy(result_paths, list.paths, list.count * sizeof(*result_paths));
    result_paths[list.count] = NULL;
    free(list.paths);
    *out_paths = result_paths;
    return list.count;

error:
    for (size_t i = 0; i < list.count; ++i)
        free(list.paths[i]);
    free(list.paths);
    return SIZE_MAX;
}