#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
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
};

static int target_name_matches(const char *name, const struct target_file_list *list)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < list->ext_count; i++) {
        const char *ext = list->exts[i];
        size_t ext_len;

        if (ext == NULL)
            continue;
        ext_len = strlen(ext);
        if (ext_len <= name_len &&
            memcmp(name + name_len - ext_len, ext, ext_len) == 0)
            return 1;
    }
    return 0;
}

static int target_list_append(struct target_file_list *list, char *path)
{
    if (list->count + 1 >= list->capacity) {
        size_t new_capacity;
        char **new_paths;

        if (list->capacity == 0) {
            new_capacity = 16;
        } else {
            if (list->capacity > SIZE_MAX / (2 * sizeof(*list->paths))) {
                errno = ENOMEM;
                return -1;
            }
            new_capacity = list->capacity * 2;
        }

        new_paths = realloc(list->paths, new_capacity * sizeof(*new_paths));
        if (new_paths == NULL)
            return -1;
        list->paths = new_paths;
        list->capacity = new_capacity;
    }

    list->paths[list->count++] = path;
    list->paths[list->count] = NULL;
    return 0;
}

static int target_walk_dir(const char *directory, struct target_file_list *list)
{
    DIR *dir = opendir(directory);
    struct dirent *entry;

    if (dir == NULL)
        return errno == ENOMEM ? -1 : 0;

    for (;;) {
        size_t dir_len, name_len;
        char *path;
        struct stat st;

        errno = 0;
        entry = readdir(dir);
        if (entry == NULL) {
            int read_error = errno;

            if (closedir(dir) != 0)
                return -1;
            if (read_error != 0 && read_error != EACCES &&
                read_error != EPERM) {
                errno = read_error;
                return -1;
            }
            return 0;
        }

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        dir_len = strlen(directory);
        name_len = strlen(entry->d_name);
        if (dir_len > SIZE_MAX - name_len - 2) {
            errno = ENOMEM;
            closedir(dir);
            return -1;
        }

        path = malloc(dir_len + name_len + 2);
        if (path == NULL) {
            closedir(dir);
            return -1;
        }
        memcpy(path, directory, dir_len);
        path[dir_len] = '/';
        memcpy(path + dir_len + 1, entry->d_name, name_len + 1);

        if (lstat(path, &st) != 0) {
            int stat_error = errno;

            free(path);
            if (stat_error == ENOMEM) {
                closedir(dir);
                errno = stat_error;
                return -1;
            }
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            int result = target_walk_dir(path, list);

            free(path);
            if (result != 0) {
                int saved_errno = errno;

                closedir(dir);
                errno = saved_errno;
                return -1;
            }
        } else if (S_ISREG(st.st_mode) &&
                   target_name_matches(entry->d_name, list)) {
            if (target_list_append(list, path) != 0) {
                int saved_errno = errno;

                free(path);
                closedir(dir);
                errno = saved_errno;
                return -1;
            }
        } else {
            free(path);
        }
    }
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    struct target_file_list list = {0};

    if (out_paths == NULL) {
        errno = EINVAL;
        return (size_t)-1;
    }
    *out_paths = NULL;

    if ((dir_count != 0 && dirs == NULL) ||
        (ext_count != 0 && exts == NULL)) {
        errno = EINVAL;
        return (size_t)-1;
    }
    if (dir_count == 0 || ext_count == 0)
        return 0;

    list.exts = exts;
    list.ext_count = ext_count;

    for (size_t i = 0; i < dir_count; i++) {
        const char *directory = dirs[i];
        char *expanded = NULL;
        int result;

        if (directory == NULL)
            continue;

        if (directory[0] == '~') {
            const char *home = getenv("HOME");
            size_t home_len, suffix_len;

            if (home == NULL) {
                errno = ENOENT;
                goto fail;
            }

            home_len = strlen(home);
            suffix_len = strlen(directory + 1);
            if (home_len > SIZE_MAX - suffix_len - 1) {
                errno = ENOMEM;
                goto fail;
            }

            expanded = malloc(home_len + suffix_len + 1);
            if (expanded == NULL)
                goto fail;
            memcpy(expanded, home, home_len);
            memcpy(expanded + home_len, directory + 1, suffix_len + 1);
            directory = expanded;
        }

        result = target_walk_dir(directory, &list);
        free(expanded);
        if (result != 0)
            goto fail;
    }

    *out_paths = list.paths;
    return list.count;

fail:
    {
        int saved_errno = errno;

        for (size_t i = 0; i < list.count; i++)
            free(list.paths[i]);
        free(list.paths);
        errno = saved_errno;
    }
    return (size_t)-1;
}