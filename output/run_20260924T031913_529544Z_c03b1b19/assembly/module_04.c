#define _GNU_SOURCE
#include <dirent.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct target_file_list {
    char **paths;
    size_t count;
    size_t capacity;
};

static char *target_join_path(const char *directory, const char *name)
{
    size_t directory_length = strlen(directory);
    size_t name_length = strlen(name);
    int add_slash = directory_length > 0 &&
                    directory[directory_length - 1] != '/';
    size_t total;

    if (directory_length > SIZE_MAX - name_length)
        return NULL;
    total = directory_length + name_length;
    if (add_slash) {
        if (total == SIZE_MAX)
            return NULL;
        total++;
    }
    if (total == SIZE_MAX)
        return NULL;

    char *result = malloc(total + 1);
    if (result == NULL)
        return NULL;

    memcpy(result, directory, directory_length);
    if (add_slash)
        result[directory_length++] = '/';
    memcpy(result + directory_length, name, name_length + 1);
    return result;
}

static int target_has_extension(const char *name,
                                const char *const *extensions,
                                size_t extension_count)
{
    size_t name_length = strlen(name);

    if (extensions == NULL)
        return 0;

    for (size_t i = 0; i < extension_count; i++) {
        if (extensions[i] == NULL)
            continue;

        size_t extension_length = strlen(extensions[i]);
        if (name_length >= extension_length &&
            memcmp(name + name_length - extension_length,
                   extensions[i], extension_length) == 0)
            return 1;
    }

    return 0;
}

static int target_append_path(struct target_file_list *list, char *path)
{
    if (list->count > SIZE_MAX - 2)
        return -1;

    size_t needed = list->count + 2;
    if (needed > list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 16 : list->capacity;

        while (new_capacity < needed) {
            if (new_capacity > SIZE_MAX / 2) {
                new_capacity = needed;
                break;
            }
            new_capacity *= 2;
        }

        if (new_capacity > SIZE_MAX / sizeof(*list->paths))
            return -1;

        char **new_paths = realloc(list->paths,
                                   new_capacity * sizeof(*list->paths));
        if (new_paths == NULL)
            return -1;

        list->paths = new_paths;
        list->capacity = new_capacity;
    }

    list->paths[list->count++] = path;
    list->paths[list->count] = NULL;
    return 0;
}

static int target_walk_directory(DIR *directory, const char *display_path,
                                 const char *const *extensions,
                                 size_t extension_count,
                                 struct target_file_list *list)
{
    int result = 0;
    int directory_fd = dirfd(directory);
    struct dirent *entry;

    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        struct stat status;
        if (fstatat(directory_fd, entry->d_name, &status,
                    AT_SYMLINK_NOFOLLOW) != 0)
            continue;

        if (!S_ISREG(status.st_mode) && !S_ISDIR(status.st_mode))
            continue;

        char *child_path = target_join_path(display_path, entry->d_name);
        if (child_path == NULL) {
            result = -1;
            break;
        }

        if (S_ISREG(status.st_mode)) {
            if (target_has_extension(entry->d_name, extensions,
                                     extension_count)) {
                if (target_append_path(list, child_path) != 0) {
                    free(child_path);
                    result = -1;
                    break;
                }
            } else {
                free(child_path);
            }
            continue;
        }

        int child_fd = openat(directory_fd, entry->d_name,
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (child_fd < 0) {
            free(child_path);
            continue;
        }

        DIR *child_directory = fdopendir(child_fd);
        if (child_directory == NULL) {
            close(child_fd);
            free(child_path);
            continue;
        }

        if (target_walk_directory(child_directory, child_path, extensions,
                                  extension_count, list) != 0)
            result = -1;

        free(child_path);
        if (result != 0)
            break;
    }

    closedir(directory);
    return result;
}

static char *target_expand_home(const char *path)
{
    if (path[0] != '~' || (path[1] != '\0' && path[1] != '/'))
        return strdup(path);

    const char *home = getenv("HOME");
    if (home == NULL)
        return NULL;

    size_t home_length = strlen(home);
    size_t remainder_length = strlen(path + 1);
    if (home_length > SIZE_MAX - remainder_length ||
        home_length + remainder_length == SIZE_MAX)
        return NULL;

    char *expanded = malloc(home_length + remainder_length + 1);
    if (expanded == NULL)
        return NULL;

    memcpy(expanded, home, home_length);
    memcpy(expanded + home_length, path + 1, remainder_length + 1);
    return expanded;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (out_paths == NULL)
        return 0;

    *out_paths = NULL;
    if (dirs == NULL || ext_count == 0 || exts == NULL)
        return 0;

    struct target_file_list list = {0};

    for (size_t i = 0; i < dir_count; i++) {
        if (dirs[i] == NULL)
            continue;

        char *expanded_path = target_expand_home(dirs[i]);
        if (expanded_path == NULL) {
            if (dirs[i][0] == '~' &&
                (dirs[i][1] == '\0' || dirs[i][1] == '/'))
                continue;
            goto allocation_error;
        }

        DIR *directory = opendir(expanded_path);
        if (directory != NULL &&
            target_walk_directory(directory, expanded_path, exts, ext_count,
                                  &list) != 0) {
            free(expanded_path);
            goto allocation_error;
        }

        free(expanded_path);
    }

    *out_paths = list.paths;
    return list.count;

allocation_error:
    for (size_t i = 0; i < list.count; i++)
        free(list.paths[i]);
    free(list.paths);
    return 0;
}