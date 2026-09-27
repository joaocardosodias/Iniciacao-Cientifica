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

static char *target_path_join(const char *directory, const char *name)
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

static int target_has_suffix(const char *name, const char *const *exts,
                             size_t ext_count)
{
    size_t name_length = strlen(name);

    for (size_t i = 0; i < ext_count; ++i) {
        if (exts[i] == NULL)
            continue;

        size_t extension_length = strlen(exts[i]);
        if (extension_length <= name_length &&
            memcmp(name + name_length - extension_length, exts[i],
                   extension_length) == 0)
            return 1;
    }

    return 0;
}

static int target_file_list_add(struct target_file_list *list, char *path)
{
    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 16 : list->capacity * 2;
        if (new_capacity < list->capacity ||
            new_capacity > SIZE_MAX / sizeof(*list->paths) - 1)
            return -1;

        char **new_paths = realloc(list->paths,
                                   (new_capacity + 1) * sizeof(*list->paths));
        if (new_paths == NULL)
            return -1;

        list->paths = new_paths;
        list->capacity = new_capacity;
    }

    list->paths[list->count++] = path;
    list->paths[list->count] = NULL;
    return 0;
}

static int target_walk_directory(const char *directory,
                                 const char *const *exts, size_t ext_count,
                                 struct target_file_list *list)
{
    DIR *stream = opendir(directory);
    if (stream == NULL)
        return 0;

    struct dirent *entry;
    int result = 0;

    while ((entry = readdir(stream)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *path = target_path_join(directory, entry->d_name);
        if (path == NULL) {
            result = -1;
            break;
        }

        struct stat status;
        if (lstat(path, &status) != 0) {
            free(path);
            continue;
        }

        if (S_ISDIR(status.st_mode)) {
            result = target_walk_directory(path, exts, ext_count, list);
            free(path);
            if (result != 0)
                break;
            continue;
        }

        if (S_ISLNK(status.st_mode)) {
            if (stat(path, &status) != 0 || !S_ISREG(status.st_mode)) {
                free(path);
                continue;
            }
        } else if (!S_ISREG(status.st_mode)) {
            free(path);
            continue;
        }

        if (target_has_suffix(entry->d_name, exts, ext_count)) {
            if (target_file_list_add(list, path) != 0) {
                free(path);
                result = -1;
                break;
            }
        } else {
            free(path);
        }
    }

    closedir(stream);
    return result;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (out_paths == NULL)
        return 0;

    *out_paths = NULL;
    if (dirs == NULL || exts == NULL)
        return 0;

    struct target_file_list list = {0};

    for (size_t i = 0; i < dir_count; ++i) {
        if (dirs[i] == NULL)
            continue;

        const char *directory = dirs[i];
        char *expanded = NULL;

        if (directory[0] == '~') {
            const char *home = getenv("HOME");
            if (home == NULL)
                continue;

            size_t home_length = strlen(home);
            size_t remainder_length = strlen(directory + 1);
            if (home_length > SIZE_MAX - remainder_length - 1)
                goto error;

            expanded = malloc(home_length + remainder_length + 1);
            if (expanded == NULL)
                goto error;

            memcpy(expanded, home, home_length);
            memcpy(expanded + home_length, directory + 1,
                   remainder_length + 1);
            directory = expanded;
        }

        int result = target_walk_directory(directory, exts, ext_count, &list);
        free(expanded);
        if (result != 0)
            goto error;
    }

    if (list.count != 0)
        *out_paths = list.paths;
    else
        free(list.paths);

    return list.count;

error:
    for (size_t i = 0; i < list.count; ++i)
        free(list.paths[i]);
    free(list.paths);
    return 0;
}