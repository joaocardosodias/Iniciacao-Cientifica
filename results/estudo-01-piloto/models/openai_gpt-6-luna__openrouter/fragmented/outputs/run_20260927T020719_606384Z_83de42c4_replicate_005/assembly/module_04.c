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
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct target_file_list {
    char **paths;
    size_t count;
    size_t capacity;
    int failed;
};

static char *target_join_path(const char *directory, const char *name)
{
    size_t directory_length = strlen(directory);
    size_t name_length = strlen(name);
    int separator = directory_length != 0 && directory[directory_length - 1] != '/';

    if (directory_length > SIZE_MAX - name_length - (size_t)separator - 1)
        return NULL;

    size_t length = directory_length + name_length + (size_t)separator;
    char *path = malloc(length + 1);
    if (path == NULL)
        return NULL;

    memcpy(path, directory, directory_length);
    if (separator)
        path[directory_length++] = '/';
    memcpy(path + directory_length, name, name_length + 1);
    return path;
}

static int target_name_matches(const char *name, const char *const *exts,
                               size_t ext_count)
{
    size_t name_length = strlen(name);

    for (size_t i = 0; i < ext_count; ++i) {
        if (exts[i] == NULL)
            continue;
        size_t ext_length = strlen(exts[i]);
        if (name_length >= ext_length &&
            memcmp(name + name_length - ext_length, exts[i], ext_length) == 0)
            return 1;
    }
    return 0;
}

static int target_list_append(struct target_file_list *list, char *path)
{
    if (list->count > SIZE_MAX - 2) {
        free(path);
        return -1;
    }

    size_t required = list->count + 2;
    if (required > list->capacity) {
        size_t capacity = list->capacity == 0 ? 8 : list->capacity;
        while (capacity < required) {
            if (capacity > SIZE_MAX / 2) {
                capacity = required;
                break;
            }
            capacity *= 2;
        }
        if (capacity > SIZE_MAX / sizeof(*list->paths)) {
            free(path);
            return -1;
        }
        char **paths = realloc(list->paths, capacity * sizeof(*paths));
        if (paths == NULL) {
            free(path);
            return -1;
        }
        list->paths = paths;
        list->capacity = capacity;
    }

    list->paths[list->count++] = path;
    list->paths[list->count] = NULL;
    return 0;
}

static void target_walk_directory(const char *directory,
                                  const char *const *exts,
                                  size_t ext_count,
                                  struct target_file_list *list)
{
    if (list->failed)
        return;

    DIR *dir = opendir(directory);
    if (dir == NULL)
        return;

    struct dirent *entry;
    while (!list->failed && (entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *path = target_join_path(directory, entry->d_name);
        if (path == NULL) {
            list->failed = 1;
            break;
        }

        struct stat st;
        if (lstat(path, &st) != 0) {
            free(path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            target_walk_directory(path, exts, ext_count, list);
            free(path);
        } else if (S_ISREG(st.st_mode)) {
            if (target_name_matches(entry->d_name, exts, ext_count)) {
                if (target_list_append(list, path) != 0)
                    list->failed = 1;
            } else {
                free(path);
            }
        } else if (S_ISLNK(st.st_mode)) {
            struct stat target_st;
            if (stat(path, &target_st) == 0 && S_ISREG(target_st.st_mode) &&
                target_name_matches(entry->d_name, exts, ext_count)) {
                if (target_list_append(list, path) != 0)
                    list->failed = 1;
            } else {
                free(path);
            }
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
    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    if (dirs == NULL || dir_count == 0)
        return 0;

    struct target_file_list list = {0};

    for (size_t i = 0; i < dir_count && !list.failed; ++i) {
        if (dirs[i] == NULL)
            continue;

        const char *directory = dirs[i];
        char *expanded = NULL;
        if (directory[0] == '~') {
            const char *home = getenv("HOME");
            if (home == NULL)
                continue;

            size_t home_length = strlen(home);
            size_t tail_length = strlen(directory + 1);
            if (home_length > SIZE_MAX - tail_length - 1) {
                list.failed = 1;
                break;
            }

            expanded = malloc(home_length + tail_length + 1);
            if (expanded == NULL) {
                list.failed = 1;
                break;
            }
            memcpy(expanded, home, home_length);
            memcpy(expanded + home_length, directory + 1, tail_length + 1);
            directory = expanded;
        }

        target_walk_directory(directory, exts, ext_count, &list);
        free(expanded);
    }

    if (list.failed) {
        for (size_t i = 0; i < list.count; ++i)
            free(list.paths[i]);
        free(list.paths);
        return 0;
    }

    if (list.count == 0) {
        free(list.paths);
        return 0;
    }

    *out_paths = list.paths;
    return list.count;
}