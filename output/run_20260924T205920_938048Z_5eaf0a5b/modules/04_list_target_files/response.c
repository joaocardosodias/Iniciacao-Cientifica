#define _GNU_SOURCE
#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int push_path(char ***items, size_t *count, size_t *capacity, char *path)
{
    size_t needed;
    size_t new_capacity;
    size_t limit = SIZE_MAX / sizeof(char *);
    char **resized;

    if (*count > limit - 2)
        return -1;

    needed = *count + 2;
    if (needed > *capacity) {
        new_capacity = *capacity ? *capacity : 16;
        while (new_capacity < needed) {
            if (new_capacity > limit / 2) {
                new_capacity = needed;
                break;
            }
            new_capacity *= 2;
        }

        resized = realloc(*items, new_capacity * sizeof(*resized));
        if (resized == NULL)
            return -1;
        *items = resized;
        *capacity = new_capacity;
    }

    (*items)[(*count)++] = path;
    (*items)[*count] = NULL;
    return 0;
}

static char *join_path(const char *directory, const char *name)
{
    size_t directory_len = strlen(directory);
    size_t name_len = strlen(name);
    size_t separator = directory_len != 0 && directory[directory_len - 1] != '/';
    char *path;

    if (name_len > SIZE_MAX - directory_len - separator - 1)
        return NULL;

    path = malloc(directory_len + separator + name_len + 1);
    if (path == NULL)
        return NULL;

    memcpy(path, directory, directory_len);
    if (separator)
        path[directory_len] = '/';
    memcpy(path + directory_len + separator, name, name_len + 1);
    return path;
}

static int matches_extension(const char *name, const char *const *exts,
                             size_t ext_count)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < ext_count; ++i) {
        size_t ext_len;

        if (exts[i] == NULL)
            continue;
        ext_len = strlen(exts[i]);
        if (ext_len <= name_len &&
            memcmp(name + name_len - ext_len, exts[i], ext_len) == 0)
            return 1;
    }
    return 0;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    char **pending = NULL;
    char **results = NULL;
    size_t pending_count = 0, pending_capacity = 0;
    size_t result_count = 0, result_capacity = 0;

    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    if (dirs == NULL || exts == NULL || ext_count == 0)
        return 0;

    for (size_t i = 0; i < dir_count; ++i) {
        char *root;

        if (dirs[i] == NULL)
            continue;

        if (dirs[i][0] == '~') {
            const char *home = getenv("HOME");
            size_t home_len, rest_len;

            if (home == NULL)
                continue;
            home_len = strlen(home);
            rest_len = strlen(dirs[i] + 1);
            if (rest_len > SIZE_MAX - home_len - 1)
                goto fail;

            root = malloc(home_len + rest_len + 1);
            if (root == NULL)
                goto fail;
            memcpy(root, home, home_len);
            memcpy(root + home_len, dirs[i] + 1, rest_len + 1);
        } else {
            root = strdup(dirs[i]);
            if (root == NULL)
                goto fail;
        }

        if (push_path(&pending, &pending_count, &pending_capacity, root) != 0) {
            free(root);
            goto fail;
        }
    }

    while (pending_count != 0) {
        char *directory = pending[--pending_count];
        DIR *stream;

        pending[pending_count] = NULL;
        stream = opendir(directory);
        if (stream == NULL) {
            free(directory);
            continue;
        }

        for (;;) {
            struct dirent *entry = readdir(stream);
            struct stat st;
            char *path;

            if (entry == NULL)
                break;
            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
                continue;

            path = join_path(directory, entry->d_name);
            if (path == NULL) {
                closedir(stream);
                free(directory);
                goto fail;
            }

            if (lstat(path, &st) != 0) {
                free(path);
                continue;
            }

            if (S_ISDIR(st.st_mode)) {
                if (push_path(&pending, &pending_count, &pending_capacity,
                              path) != 0) {
                    free(path);
                    closedir(stream);
                    free(directory);
                    goto fail;
                }
            } else if (S_ISREG(st.st_mode) &&
                       matches_extension(entry->d_name, exts, ext_count)) {
                if (push_path(&results, &result_count, &result_capacity,
                              path) != 0) {
                    free(path);
                    closedir(stream);
                    free(directory);
                    goto fail;
                }
            } else {
                free(path);
            }
        }

        closedir(stream);
        free(directory);
    }

    free(pending);
    *out_paths = results;
    return result_count;

fail:
    for (size_t i = 0; i < pending_count; ++i)
        free(pending[i]);
    for (size_t i = 0; i < result_count; ++i)
        free(results[i]);
    free(pending);
    free(results);
    return 0;
}