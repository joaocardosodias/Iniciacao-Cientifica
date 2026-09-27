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
    int has_separator = directory_length > 0 &&
                        directory[directory_length - 1] == '/';
    size_t length = directory_length + (has_separator ? 0 : 1) +
                    name_length + 1;
    char *path = malloc(length);

    if (path == NULL)
        return NULL;

    memcpy(path, directory, directory_length);
    if (!has_separator)
        path[directory_length++] = '/';
    memcpy(path + directory_length, name, name_length + 1);
    return path;
}

static int target_file_matches(const char *name,
                               const char *const *exts,
                               size_t ext_count)
{
    size_t name_length = strlen(name);

    for (size_t i = 0; i < ext_count; i++) {
        if (exts[i] == NULL)
            continue;

        size_t ext_length = strlen(exts[i]);
        if (name_length >= ext_length &&
            memcmp(name + name_length - ext_length, exts[i], ext_length) == 0)
            return 1;
    }

    return 0;
}

static int target_file_append(struct target_file_list *list, char *path)
{
    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 16 : list->capacity * 2;
        char **new_paths = realloc(list->paths,
                                   new_capacity * sizeof(*new_paths));
        if (new_paths == NULL)
            return -1;
        list->paths = new_paths;
        list->capacity = new_capacity;
    }

    list->paths[list->count++] = path;
    return 0;
}

static int target_walk_directory(const char *directory,
                                 const char *const *exts,
                                 size_t ext_count,
                                 struct target_file_list *list)
{
    DIR *dir = opendir(directory);
    if (dir == NULL)
        return 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *path = target_join_path(directory, entry->d_name);
        if (path == NULL) {
            closedir(dir);
            return -1;
        }

        struct stat st;
        if (lstat(path, &st) != 0) {
            free(path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            int result = target_walk_directory(path, exts, ext_count, list);
            free(path);
            if (result != 0) {
                closedir(dir);
                return -1;
            }
        } else if (S_ISREG(st.st_mode) &&
                   target_file_matches(entry->d_name, exts, ext_count)) {
            if (target_file_append(list, path) != 0) {
                free(path);
                closedir(dir);
                return -1;
            }
        } else {
            free(path);
        }
    }

    closedir(dir);
    return 0;
}

static char *target_expand_home(const char *directory)
{
    if (directory[0] != '~')
        return strdup(directory);

    const char *home = getenv("HOME");
    if (home == NULL)
        return NULL;

    size_t home_length = strlen(home);
    size_t remainder_length = strlen(directory + 1);
    char *expanded = malloc(home_length + remainder_length + 1);
    if (expanded == NULL)
        return NULL;

    memcpy(expanded, home, home_length);
    memcpy(expanded + home_length, directory + 1, remainder_length + 1);
    return expanded;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (out_paths == NULL)
        return 0;

    *out_paths = NULL;
    struct target_file_list list = {0};

    for (size_t i = 0; i < dir_count; i++) {
        if (dirs == NULL || dirs[i] == NULL)
            continue;

        char *directory = target_expand_home(dirs[i]);
        if (directory == NULL) {
            if (dirs[i][0] == '~' && getenv("HOME") == NULL)
                continue;

            for (size_t j = 0; j < list.count; j++)
                free(list.paths[j]);
            free(list.paths);
            return 0;
        }

        int result = target_walk_directory(directory, exts, ext_count, &list);
        free(directory);
        if (result != 0) {
            for (size_t j = 0; j < list.count; j++)
                free(list.paths[j]);
            free(list.paths);
            return 0;
        }
    }

    if (list.count == 0) {
        free(list.paths);
        return 0;
    }

    list.paths[list.count] = NULL;
    *out_paths = list.paths;
    return list.count;
}