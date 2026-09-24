#define _GNU_SOURCE
#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int lt_push(char ***items, size_t *count, size_t *capacity, char *path)
{
    char **grown;
    size_t maximum = SIZE_MAX / sizeof(char *) - 1;
    size_t new_capacity;

    if (*count >= maximum)
        return -1;

    if (*count == *capacity) {
        if (*capacity == 0)
            new_capacity = 16;
        else if (*capacity > maximum / 2)
            new_capacity = maximum;
        else
            new_capacity = *capacity * 2;

        grown = realloc(*items, new_capacity * sizeof(char *));
        if (grown == NULL)
            return -1;

        *items = grown;
        *capacity = new_capacity;
    }

    (*items)[(*count)++] = path;
    return 0;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    char **pending = NULL;
    char **paths = NULL;
    char *active = NULL;
    DIR *stream = NULL;
    size_t pending_count = 0, pending_capacity = 0;
    size_t path_count = 0, path_capacity = 0;
    size_t i;

    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    if (dirs == NULL || exts == NULL || ext_count == 0)
        return 0;

    for (i = 0; i < dir_count; ++i) {
        const char *source = dirs[i];
        char *root;

        if (source == NULL)
            continue;

        if (source[0] == '~') {
            const char *home = getenv("HOME");
            size_t home_len, rest_len;

            if (home == NULL)
                continue;

            home_len = strlen(home);
            rest_len = strlen(source + 1);
            if (home_len > SIZE_MAX - rest_len - 1)
                goto fail;

            root = malloc(home_len + rest_len + 1);
            if (root == NULL)
                goto fail;
            memcpy(root, home, home_len);
            memcpy(root + home_len, source + 1, rest_len + 1);
        } else {
            root = strdup(source);
            if (root == NULL)
                goto fail;
        }

        if (lt_push(&pending, &pending_count, &pending_capacity, root) != 0) {
            free(root);
            goto fail;
        }
    }

    while (pending_count != 0) {
        struct dirent *entry;
        int directory_fd;

        active = pending[--pending_count];
        stream = opendir(active);
        if (stream == NULL) {
            free(active);
            active = NULL;
            continue;
        }

        directory_fd = dirfd(stream);
        if (directory_fd < 0)
            goto fail;

        while ((entry = readdir(stream)) != NULL) {
            struct stat info;
            size_t name_len, parent_len, separator_len;
            char *child;

            if (entry->d_name[0] == '.' &&
                (entry->d_name[1] == '\0' ||
                 (entry->d_name[1] == '.' && entry->d_name[2] == '\0')))
                continue;

            if (fstatat(directory_fd, entry->d_name, &info,
                        AT_SYMLINK_NOFOLLOW) != 0)
                continue;

            if (!S_ISDIR(info.st_mode) && !S_ISREG(info.st_mode))
                continue;

            name_len = strlen(entry->d_name);
            if (S_ISREG(info.st_mode)) {
                size_t j;
                int matches = 0;

                for (j = 0; j < ext_count; ++j) {
                    size_t ext_len;

                    if (exts[j] == NULL)
                        continue;
                    ext_len = strlen(exts[j]);
                    if (ext_len <= name_len &&
                        memcmp(entry->d_name + name_len - ext_len,
                               exts[j], ext_len) == 0) {
                        matches = 1;
                        break;
                    }
                }
                if (!matches)
                    continue;
            }

            parent_len = strlen(active);
            separator_len = parent_len != 0 && active[parent_len - 1] == '/'
                                ? 0 : 1;
            if (parent_len > SIZE_MAX - separator_len - name_len - 1)
                goto fail;

            child = malloc(parent_len + separator_len + name_len + 1);
            if (child == NULL)
                goto fail;

            memcpy(child, active, parent_len);
            if (separator_len != 0)
                child[parent_len] = '/';
            memcpy(child + parent_len + separator_len, entry->d_name,
                   name_len + 1);

            if (S_ISDIR(info.st_mode)) {
                if (lt_push(&pending, &pending_count, &pending_capacity,
                            child) != 0) {
                    free(child);
                    goto fail;
                }
            } else {
                if (lt_push(&paths, &path_count, &path_capacity, child) != 0) {
                    free(child);
                    goto fail;
                }
            }
        }

        closedir(stream);
        stream = NULL;
        free(active);
        active = NULL;
    }

    free(pending);

    if (path_count == 0) {
        free(paths);
        return 0;
    }

    {
        char **result = realloc(paths, (path_count + 1) * sizeof(char *));
        if (result == NULL)
            goto fail;
        paths = result;
    }

    paths[path_count] = NULL;
    *out_paths = paths;
    return path_count;

fail:
    if (stream != NULL)
        closedir(stream);
    free(active);
    for (i = 0; i < pending_count; ++i)
        free(pending[i]);
    free(pending);
    for (i = 0; i < path_count; ++i)
        free(paths[i]);
    free(paths);
    return 0;
}