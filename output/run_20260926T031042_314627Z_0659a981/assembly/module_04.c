#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <syslog.h>
#include <wchar.h>
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

static char *target_join_path(const char *directory, const char *name)
{
    size_t directory_length = strlen(directory);
    size_t name_length = strlen(name);
    int separator = directory_length != 0 &&
                    directory[directory_length - 1] != '/';

    if (directory_length > SIZE_MAX - name_length - (size_t)separator - 1)
        return NULL;

    size_t length = directory_length + (size_t)separator + name_length;
    char *path = malloc(length + 1);
    if (path == NULL)
        return NULL;

    memcpy(path, directory, directory_length);
    if (separator)
        path[directory_length++] = '/';
    memcpy(path + directory_length, name, name_length + 1);
    return path;
}

static int target_has_extension(const char *name,
                                const char *const *extensions,
                                size_t extension_count)
{
    size_t name_length = strlen(name);

    for (size_t i = 0; i < extension_count; ++i) {
        if (extensions[i] == NULL)
            continue;

        size_t extension_length = strlen(extensions[i]);
        if (extension_length <= name_length &&
            memcmp(name + name_length - extension_length,
                   extensions[i], extension_length) == 0)
            return 1;
    }
    return 0;
}

static int target_append_path(struct target_file_list *list, const char *path)
{
    char *copy = strdup(path);
    if (copy == NULL)
        return -1;

    if (list->count > SIZE_MAX - 2) {
        free(copy);
        return -1;
    }

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
        if (capacity > SIZE_MAX / sizeof(*list->paths)) {
            free(copy);
            return -1;
        }

        char **paths = realloc(list->paths, capacity * sizeof(*paths));
        if (paths == NULL) {
            free(copy);
            return -1;
        }
        list->paths = paths;
        list->capacity = capacity;
    }

    list->paths[list->count++] = copy;
    list->paths[list->count] = NULL;
    return 0;
}

static int target_walk_directory(const char *path,
                                 const char *const *extensions,
                                 size_t extension_count,
                                 struct target_file_list *list)
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

        struct stat status;
        if (lstat(child, &status) == 0) {
            if (S_ISDIR(status.st_mode)) {
                if (target_walk_directory(child, extensions, extension_count,
                                          list) < 0) {
                    free(child);
                    closedir(directory);
                    return -1;
                }
            } else if (S_ISREG(status.st_mode) &&
                       target_has_extension(entry->d_name, extensions,
                                            extension_count)) {
                if (target_append_path(list, child) < 0) {
                    free(child);
                    closedir(directory);
                    return -1;
                }
            }
        }
        free(child);
    }

    closedir(directory);
    return 0;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    if (dirs == NULL || exts == NULL || ext_count == 0)
        return 0;

    struct target_file_list list = {0};

    for (size_t i = 0; i < dir_count; ++i) {
        if (dirs[i] == NULL)
            continue;

        const char *directory = dirs[i];
        char *expanded = NULL;
        if (directory[0] == '~' &&
            (directory[1] == '\0' || directory[1] == '/')) {
            const char *home = getenv("HOME");
            if (home == NULL)
                continue;

            size_t home_length = strlen(home);
            size_t suffix_length = strlen(directory + 1);
            if (home_length > SIZE_MAX - suffix_length - 1)
                goto allocation_failure;

            expanded = malloc(home_length + suffix_length + 1);
            if (expanded == NULL)
                goto allocation_failure;
            memcpy(expanded, home, home_length);
            memcpy(expanded + home_length, directory + 1,
                   suffix_length + 1);
            directory = expanded;
        }

        int result = target_walk_directory(directory, exts, ext_count, &list);
        free(expanded);
        if (result < 0)
            goto allocation_failure;
    }

    *out_paths = list.paths;
    return list.count;

allocation_failure:
    for (size_t i = 0; i < list.count; ++i)
        free(list.paths[i]);
    free(list.paths);
    return 0;
}