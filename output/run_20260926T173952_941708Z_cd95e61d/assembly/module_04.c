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

struct path_list {
    char **items;
    size_t count;
    size_t capacity;
};

static int
path_list_append(struct path_list *list, char *path)
{
    if (list->count > SIZE_MAX / sizeof(*list->items) - 2)
        return -1;

    if (list->count + 1 >= list->capacity) {
        size_t new_capacity = list->capacity ? list->capacity : 16;

        while (new_capacity <= list->count + 1) {
            if (new_capacity > SIZE_MAX / 2)
                return -1;
            new_capacity *= 2;
        }

        if (new_capacity > SIZE_MAX / sizeof(*list->items))
            return -1;

        char **new_items = realloc(list->items,
                                   new_capacity * sizeof(*list->items));
        if (!new_items)
            return -1;
        list->items = new_items;
        list->capacity = new_capacity;
    }

    list->items[list->count++] = path;
    return 0;
}

static char *
join_path(const char *directory, const char *name)
{
    size_t directory_length = strlen(directory);
    size_t name_length = strlen(name);
    int needs_slash = directory_length == 0 ||
                      directory[directory_length - 1] != '/';

    if (directory_length > SIZE_MAX - name_length - (size_t)needs_slash - 1)
        return NULL;

    size_t length = directory_length + (size_t)needs_slash + name_length + 1;
    char *result = malloc(length);
    if (!result)
        return NULL;

    memcpy(result, directory, directory_length);
    size_t offset = directory_length;
    if (needs_slash)
        result[offset++] = '/';
    memcpy(result + offset, name, name_length + 1);
    return result;
}

static int
matches_extension(const char *name, const char *const *exts,
                  size_t ext_count)
{
    size_t name_length = strlen(name);

    for (size_t i = 0; i < ext_count; i++) {
        if (!exts[i])
            continue;
        size_t extension_length = strlen(exts[i]);
        if (extension_length <= name_length &&
            memcmp(name + name_length - extension_length,
                   exts[i], extension_length) == 0)
            return 1;
    }
    return 0;
}

static int
walk_directory(const char *path, const char *const *exts, size_t ext_count,
               struct path_list *list)
{
    DIR *directory = opendir(path);
    if (!directory)
        return 0;

    struct dirent *entry;
    while ((entry = readdir(directory)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *child_path = join_path(path, entry->d_name);
        if (!child_path) {
            closedir(directory);
            return -1;
        }

        struct stat info;
        if (lstat(child_path, &info) != 0) {
            free(child_path);
            continue;
        }

        if (S_ISDIR(info.st_mode)) {
            int result = walk_directory(child_path, exts, ext_count, list);
            free(child_path);
            if (result != 0) {
                closedir(directory);
                return -1;
            }
            continue;
        }

        if (S_ISLNK(info.st_mode) && stat(child_path, &info) != 0) {
            free(child_path);
            continue;
        }

        if (S_ISREG(info.st_mode) &&
            matches_extension(entry->d_name, exts, ext_count)) {
            if (path_list_append(list, child_path) != 0) {
                free(child_path);
                closedir(directory);
                return -1;
            }
        } else {
            free(child_path);
        }
    }

    closedir(directory);
    return 0;
}

size_t
list_target_files(const char *const *dirs, size_t dir_count,
                  const char *const *exts, size_t ext_count,
                  char ***out_paths)
{
    if (!out_paths)
        return 0;
    *out_paths = NULL;

    if ((dir_count != 0 && !dirs) || (ext_count != 0 && !exts))
        return 0;

    struct path_list list = {0};

    for (size_t i = 0; i < dir_count; i++) {
        if (!dirs[i])
            continue;

        const char *path = dirs[i];
        char *expanded_path = NULL;

        if (path[0] == '~') {
            const char *home = getenv("HOME");
            if (!home)
                continue;

            size_t home_length = strlen(home);
            size_t remainder_length = strlen(path + 1);
            if (home_length > SIZE_MAX - remainder_length - 1)
                goto failure;

            expanded_path = malloc(home_length + remainder_length + 1);
            if (!expanded_path)
                goto failure;

            memcpy(expanded_path, home, home_length);
            memcpy(expanded_path + home_length, path + 1,
                   remainder_length + 1);
            path = expanded_path;
        }

        int result = walk_directory(path, exts, ext_count, &list);
        free(expanded_path);
        if (result != 0)
            goto failure;
    }

    if (list.count == 0) {
        free(list.items);
        return 0;
    }

    if (list.count == SIZE_MAX / sizeof(*list.items)) 
        goto failure;

    char **result = realloc(list.items,
                            (list.count + 1) * sizeof(*list.items));
    if (!result)
        goto failure;

    result[list.count] = NULL;
    *out_paths = result;
    return list.count;

failure:
    for (size_t i = 0; i < list.count; i++)
        free(list.items[i]);
    free(list.items);
    return 0;
}