#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct target_file_list {
    char **paths;
    size_t count;
    size_t capacity;
};

static int
target_path_matches(const char *name, const char *const *exts, size_t ext_count)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < ext_count; i++) {
        if (exts[i] == NULL)
            continue;
        size_t ext_len = strlen(exts[i]);
        if (ext_len <= name_len &&
            memcmp(name + name_len - ext_len, exts[i], ext_len) == 0)
            return 1;
    }
    return 0;
}

static int
target_list_append(struct target_file_list *list, char *path)
{
    if (list->count == list->capacity) {
        size_t new_capacity;

        if (list->capacity == 0) {
            new_capacity = 16;
        } else {
            if (list->capacity > SIZE_MAX / 2)
                return -1;
            new_capacity = list->capacity * 2;
        }

        char **new_paths = reallocarray(list->paths, new_capacity,
                                        sizeof(*list->paths));
        if (new_paths == NULL)
            return -1;
        list->paths = new_paths;
        list->capacity = new_capacity;
    }

    list->paths[list->count++] = path;
    list->paths[list->count] = NULL;
    return 0;
}

static char *
target_join_path(const char *directory, const char *name)
{
    size_t len = strlen(directory);

    if (len > 0 && directory[len - 1] == '/') {
        char *result = NULL;
        if (asprintf(&result, "%s%s", directory, name) < 0)
            return NULL;
        return result;
    }

    char *result = NULL;
    if (asprintf(&result, "%s/%s", directory, name) < 0)
        return NULL;
    return result;
}

static int
target_walk_directory(const char *path, const char *const *exts,
                      size_t ext_count, struct target_file_list *list)
{
    DIR *directory = opendir(path);
    if (directory == NULL)
        return 0;

    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *child = target_join_path(path, entry->d_name);
        if (child == NULL) {
            closedir(directory);
            return -1;
        }

        struct stat lst;
        if (lstat(child, &lst) != 0) {
            free(child);
            continue;
        }

        if (S_ISDIR(lst.st_mode)) {
            int result = target_walk_directory(child, exts, ext_count, list);
            free(child);
            if (result != 0) {
                closedir(directory);
                return -1;
            }
            continue;
        }

        struct stat st = lst;
        if (S_ISLNK(lst.st_mode) && stat(child, &st) != 0) {
            free(child);
            continue;
        }

        if (S_ISREG(st.st_mode) &&
            target_path_matches(entry->d_name, exts, ext_count)) {
            if (target_list_append(list, child) != 0) {
                free(child);
                closedir(directory);
                return -1;
            }
        } else {
            free(child);
        }
    }

    closedir(directory);
    return 0;
}

static int
target_expand_directory(const char *directory, char **expanded)
{
    *expanded = NULL;

    if (directory[0] != '~') {
        *expanded = strdup(directory);
        return *expanded == NULL ? -1 : 0;
    }

    const char *home = getenv("HOME");
    if (home == NULL)
        return 1;

    if (asprintf(expanded, "%s%s", home, directory + 1) < 0) {
        *expanded = NULL;
        return -1;
    }
    return 0;
}

size_t
list_target_files(const char *const *dirs, size_t dir_count,
                  const char *const *exts, size_t ext_count,
                  char ***out_paths)
{
    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    if ((dir_count != 0 && dirs == NULL) ||
        (ext_count != 0 && exts == NULL))
        return 0;

    struct target_file_list list = {0};

    for (size_t i = 0; i < dir_count; i++) {
        if (dirs[i] == NULL)
            continue;

        char *expanded = NULL;
        int result = target_expand_directory(dirs[i], &expanded);
        if (result < 0)
            goto error;
        if (result > 0)
            continue;

        result = target_walk_directory(expanded, exts, ext_count, &list);
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
    for (size_t i = 0; i < list.count; i++)
        free(list.paths[i]);
    free(list.paths);
    return 0;
}