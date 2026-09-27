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

static int target_file_reserve(struct target_file_list *list, size_t needed)
{
    size_t capacity;
    char **paths;

    if (needed <= list->capacity)
        return 0;

    capacity = list->capacity ? list->capacity : 16;
    while (capacity < needed) {
        if (capacity > SIZE_MAX / 2) {
            capacity = needed;
            break;
        }
        capacity *= 2;
    }
    if (capacity > SIZE_MAX / sizeof(*paths))
        return -1;

    paths = realloc(list->paths, capacity * sizeof(*paths));
    if (paths == NULL)
        return -1;

    list->paths = paths;
    list->capacity = capacity;
    return 0;
}

static int target_file_matches(const char *name,
                               const char *const *exts,
                               size_t ext_count)
{
    size_t name_length = strlen(name);

    for (size_t i = 0; i < ext_count; ++i) {
        size_t ext_length;

        if (exts[i] == NULL)
            continue;
        ext_length = strlen(exts[i]);
        if (name_length >= ext_length &&
            memcmp(name + name_length - ext_length, exts[i], ext_length) == 0)
            return 1;
    }
    return 0;
}

static char *target_file_join(const char *directory, const char *name)
{
    size_t directory_length = strlen(directory);
    size_t name_length = strlen(name);
    int add_slash = directory_length != 0 &&
                    directory[directory_length - 1] != '/';
    size_t total;
    char *result;

    if (directory_length > SIZE_MAX - name_length - (size_t)add_slash - 1)
        return NULL;
    total = directory_length + (size_t)add_slash + name_length + 1;
    result = malloc(total);
    if (result == NULL)
        return NULL;

    memcpy(result, directory, directory_length);
    if (add_slash)
        result[directory_length++] = '/';
    memcpy(result + directory_length, name, name_length + 1);
    return result;
}

static void target_file_walk(const char *directory,
                             struct target_file_list *list)
{
    DIR *dir;
    struct dirent *entry;

    if (list->failed)
        return;

    dir = opendir(directory);
    if (dir == NULL)
        return;

    while (!list->failed && (entry = readdir(dir)) != NULL) {
        char *path;
        struct stat st;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        path = target_file_join(directory, entry->d_name);
        if (path == NULL) {
            list->failed = 1;
            break;
        }

        if (lstat(path, &st) != 0) {
            free(path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            target_file_walk(path, list);
            free(path);
        } else if (S_ISREG(st.st_mode) &&
                   target_file_matches(entry->d_name, list->exts,
                                       list->ext_count)) {
            if (list->count > SIZE_MAX - 2 ||
                target_file_reserve(list, list->count + 2) != 0) {
                free(path);
                list->failed = 1;
                break;
            }
            list->paths[list->count++] = path;
            list->paths[list->count] = NULL;
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
    struct target_file_list list = {0};

    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    list.exts = exts;
    list.ext_count = ext_count;

    if (dirs != NULL) {
        for (size_t i = 0; i < dir_count && !list.failed; ++i) {
            const char *directory = dirs[i];
            char *expanded = NULL;

            if (directory == NULL)
                continue;

            if (directory[0] == '~') {
                const char *home = getenv("HOME");
                size_t home_length;
                size_t remainder_length;

                if (home == NULL)
                    continue;
                home_length = strlen(home);
                remainder_length = strlen(directory + 1);
                if (home_length > SIZE_MAX - remainder_length - 1) {
                    list.failed = 1;
                    break;
                }
                expanded = malloc(home_length + remainder_length + 1);
                if (expanded == NULL) {
                    list.failed = 1;
                    break;
                }
                memcpy(expanded, home, home_length);
                memcpy(expanded + home_length, directory + 1,
                       remainder_length + 1);
                directory = expanded;
            }

            target_file_walk(directory, &list);
            free(expanded);
        }
    }

    if (list.failed || list.count == 0) {
        for (size_t i = 0; i < list.count; ++i)
            free(list.paths[i]);
        free(list.paths);
        return 0;
    }

    *out_paths = list.paths;
    return list.count;
}