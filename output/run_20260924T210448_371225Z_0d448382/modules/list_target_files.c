#define _GNU_SOURCE
#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct path_vector {
    char **items;
    size_t count;
    size_t capacity;
};

static int path_vector_push(struct path_vector *vector, char *path)
{
    size_t needed;
    size_t capacity;
    char **items;

    if (vector->count > SIZE_MAX - 2)
        return -1;
    needed = vector->count + 2;

    if (needed > vector->capacity) {
        capacity = vector->capacity ? vector->capacity : 16;
        while (capacity < needed) {
            if (capacity > SIZE_MAX / 2) {
                capacity = needed;
                break;
            }
            capacity *= 2;
        }
        if (capacity > SIZE_MAX / sizeof(*items))
            return -1;

        items = realloc(vector->items, capacity * sizeof(*items));
        if (!items)
            return -1;
        vector->items = items;
        vector->capacity = capacity;
    }

    vector->items[vector->count++] = path;
    vector->items[vector->count] = NULL;
    return 0;
}

static void path_vector_free(struct path_vector *vector)
{
    size_t i;

    for (i = 0; i < vector->count; ++i)
        free(vector->items[i]);
    free(vector->items);
}

static char *join_path(const char *directory, const char *name)
{
    size_t directory_len = strlen(directory);
    size_t name_len = strlen(name);
    int separator = directory_len != 0 && directory[directory_len - 1] != '/';
    size_t length;
    char *path;

    if (directory_len > SIZE_MAX - name_len)
        return NULL;
    length = directory_len + name_len;
    if (length > SIZE_MAX - (size_t)separator - 1)
        return NULL;

    path = malloc(length + (size_t)separator + 1);
    if (!path)
        return NULL;

    memcpy(path, directory, directory_len);
    if (separator)
        path[directory_len] = '/';
    memcpy(path + directory_len + (size_t)separator, name, name_len + 1);
    return path;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    struct path_vector pending = {0};
    struct path_vector found = {0};
    size_t i;

    if (!out_paths)
        return 0;
    *out_paths = NULL;

    if ((dir_count && !dirs) || (ext_count && !exts))
        return 0;

    for (i = 0; i < dir_count; ++i) {
        char *root;

        if (!dirs[i])
            continue;

        if (dirs[i][0] == '~') {
            const char *home = getenv("HOME");
            size_t home_len;
            size_t suffix_len;

            if (!home)
                continue;
            home_len = strlen(home);
            suffix_len = strlen(dirs[i] + 1);
            if (home_len > SIZE_MAX - suffix_len - 1)
                goto error;

            root = malloc(home_len + suffix_len + 1);
            if (!root)
                goto error;
            memcpy(root, home, home_len);
            memcpy(root + home_len, dirs[i] + 1, suffix_len + 1);
        } else {
            root = strdup(dirs[i]);
            if (!root)
                goto error;
        }

        if (path_vector_push(&pending, root) != 0) {
            free(root);
            goto error;
        }

        while (pending.count) {
            char *directory = pending.items[--pending.count];
            DIR *stream;

            pending.items[pending.count] = NULL;
            stream = opendir(directory);
            if (stream) {
                struct dirent *entry;

                while ((entry = readdir(stream)) != NULL) {
                    char *path;
                    struct stat st;

                    if (strcmp(entry->d_name, ".") == 0 ||
                        strcmp(entry->d_name, "..") == 0)
                        continue;

                    path = join_path(directory, entry->d_name);
                    if (!path) {
                        closedir(stream);
                        free(directory);
                        goto error;
                    }

                    if (lstat(path, &st) != 0) {
                        free(path);
                        continue;
                    }

                    if (S_ISDIR(st.st_mode)) {
                        if (path_vector_push(&pending, path) != 0) {
                            free(path);
                            closedir(stream);
                            free(directory);
                            goto error;
                        }
                    } else if (S_ISREG(st.st_mode)) {
                        size_t name_len = strlen(entry->d_name);
                        size_t j;
                        int matches = 0;

                        for (j = 0; j < ext_count; ++j) {
                            size_t ext_len;

                            if (!exts[j])
                                continue;
                            ext_len = strlen(exts[j]);
                            if (ext_len <= name_len &&
                                memcmp(entry->d_name + name_len - ext_len,
                                       exts[j], ext_len) == 0) {
                                matches = 1;
                                break;
                            }
                        }

                        if (matches) {
                            if (path_vector_push(&found, path) != 0) {
                                free(path);
                                closedir(stream);
                                free(directory);
                                goto error;
                            }
                        } else {
                            free(path);
                        }
                    } else {
                        free(path);
                    }
                }
                closedir(stream);
            }
            free(directory);
        }
    }

    free(pending.items);
    if (found.count == 0) {
        free(found.items);
        return 0;
    }

    *out_paths = found.items;
    return found.count;

error:
    path_vector_free(&pending);
    path_vector_free(&found);
    return 0;
}