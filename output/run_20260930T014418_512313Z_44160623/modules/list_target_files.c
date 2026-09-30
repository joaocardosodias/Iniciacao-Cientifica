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

static int target_file_add(struct target_file_list *list, const char *path)
{
    size_t length = strlen(path);

    if (length == SIZE_MAX || list->count == SIZE_MAX)
        return -1;

    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity ? list->capacity * 2 : 8;
        char **new_paths;

        if (new_capacity < list->capacity ||
            new_capacity > SIZE_MAX / sizeof(*list->paths) - 1)
            new_capacity = list->count + 1;
        if (new_capacity <= list->count ||
            new_capacity > SIZE_MAX / sizeof(*list->paths) - 1)
            return -1;

        new_paths = realloc(list->paths,
                            (new_capacity + 1) * sizeof(*list->paths));
        if (!new_paths)
            return -1;
        list->paths = new_paths;
        list->capacity = new_capacity;
    }

    list->paths[list->count] = malloc(length + 1);
    if (!list->paths[list->count])
        return -1;
    memcpy(list->paths[list->count], path, length + 1);
    list->count++;
    list->paths[list->count] = NULL;
    return 0;
}

static int target_file_matches(const char *name,
                               const char *const *exts,
                               size_t ext_count)
{
    size_t name_length = strlen(name);

    for (size_t i = 0; i < ext_count; i++) {
        size_t ext_length;

        if (!exts || !exts[i])
            continue;
        ext_length = strlen(exts[i]);
        if (name_length >= ext_length &&
            memcmp(name + name_length - ext_length, exts[i], ext_length) == 0)
            return 1;
    }
    return 0;
}

static char *target_file_child_path(const char *directory, const char *name)
{
    size_t directory_length = strlen(directory);
    size_t name_length = strlen(name);
    int needs_slash = directory_length != 0 &&
                      directory[directory_length - 1] != '/';
    size_t extra = (size_t)needs_slash;

    if (directory_length > SIZE_MAX - name_length ||
        directory_length + name_length > SIZE_MAX - extra - 1)
        return NULL;

    char *path = malloc(directory_length + extra + name_length + 1);
    if (!path)
        return NULL;

    memcpy(path, directory, directory_length);
    if (needs_slash)
        path[directory_length++] = '/';
    memcpy(path + directory_length, name, name_length + 1);
    return path;
}

static int target_file_walk(const char *directory,
                            const char *const *exts,
                            size_t ext_count,
                            struct target_file_list *list)
{
    DIR *dir = opendir(directory);
    struct dirent *entry;

    if (!dir)
        return 0;

    while ((entry = readdir(dir)) != NULL) {
        char *path;
        struct stat st;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        path = target_file_child_path(directory, entry->d_name);
        if (!path) {
            closedir(dir);
            return -1;
        }

        if (lstat(path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                if (target_file_walk(path, exts, ext_count, list) < 0) {
                    free(path);
                    closedir(dir);
                    return -1;
                }
            } else if (S_ISREG(st.st_mode) &&
                       target_file_matches(entry->d_name, exts, ext_count)) {
                if (target_file_add(list, path) < 0) {
                    free(path);
                    closedir(dir);
                    return -1;
                }
            }
        }
        free(path);
    }

    closedir(dir);
    return 0;
}

static char *target_file_expand_home(const char *directory)
{
    const char *home;
    size_t home_length, remainder_length;
    char *expanded;

    if (!directory || directory[0] != '~')
        return directory ? strdup(directory) : NULL;

    home = getenv("HOME");
    if (!home)
        return strdup(directory);

    home_length = strlen(home);
    remainder_length = strlen(directory + 1);
    if (home_length > SIZE_MAX - remainder_length - 1)
        return NULL;

    expanded = malloc(home_length + remainder_length + 1);
    if (!expanded)
        return NULL;
    memcpy(expanded, home, home_length);
    memcpy(expanded + home_length, directory + 1, remainder_length + 1);
    return expanded;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    struct target_file_list list = {0};

    if (!out_paths)
        return 0;
    *out_paths = NULL;

    if (!dirs)
        return 0;

    for (size_t i = 0; i < dir_count; i++) {
        char *directory;

        if (!dirs[i])
            continue;
        directory = target_file_expand_home(dirs[i]);
        if (!directory)
            goto error;
        if (target_file_walk(directory, exts, ext_count, &list) < 0) {
            free(directory);
            goto error;
        }
        free(directory);
    }

    if (list.count != 0)
        *out_paths = list.paths;
    else
        free(list.paths);
    return list.count;

error:
    for (size_t i = 0; i < list.count; i++)
        free(list.paths[i]);
    free(list.paths);
    return 0;
}