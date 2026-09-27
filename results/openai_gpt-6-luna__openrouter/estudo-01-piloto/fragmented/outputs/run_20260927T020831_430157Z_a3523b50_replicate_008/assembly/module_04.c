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
    const char *const *exts;
    size_t ext_count;
};

static int target_file_matches(const char *name,
                               const char *const *exts,
                               size_t ext_count)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < ext_count; ++i) {
        if (exts[i] == NULL)
            continue;
        size_t ext_len = strlen(exts[i]);
        if (name_len >= ext_len &&
            memcmp(name + name_len - ext_len, exts[i], ext_len) == 0)
            return 1;
    }
    return 0;
}

static char *target_file_join(const char *dir, const char *name)
{
    size_t dir_len = strlen(dir);
    size_t name_len = strlen(name);
    int add_slash = dir_len > 0 && dir[dir_len - 1] != '/';

    if (dir_len > SIZE_MAX - name_len - (size_t)add_slash - 1)
        return NULL;

    size_t total = dir_len + (size_t)add_slash + name_len + 1;
    char *path = malloc(total);
    if (path == NULL)
        return NULL;

    memcpy(path, dir, dir_len);
    size_t offset = dir_len;
    if (add_slash)
        path[offset++] = '/';
    memcpy(path + offset, name, name_len + 1);
    return path;
}

static int target_file_add(struct target_file_list *list, const char *path)
{
    if (list->count > SIZE_MAX - 2)
        return -1;

    if (list->count + 1 >= list->capacity) {
        size_t new_capacity = list->capacity ? list->capacity * 2 : 16;
        if (new_capacity < list->capacity ||
            new_capacity < list->count + 2)
            new_capacity = list->count + 2;
        if (new_capacity > SIZE_MAX / sizeof(*list->paths))
            return -1;

        char **new_paths = realloc(list->paths,
                                   new_capacity * sizeof(*list->paths));
        if (new_paths == NULL)
            return -1;
        list->paths = new_paths;
        list->capacity = new_capacity;
    }

    size_t len = strlen(path);
    if (len == SIZE_MAX)
        return -1;
    char *copy = malloc(len + 1);
    if (copy == NULL)
        return -1;
    memcpy(copy, path, len + 1);

    list->paths[list->count++] = copy;
    list->paths[list->count] = NULL;
    return 0;
}

static int target_file_walk(const char *dir, struct target_file_list *list)
{
    DIR *stream = opendir(dir);
    if (stream == NULL)
        return 0;

    int result = 0;
    struct dirent *entry;
    while ((entry = readdir(stream)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *path = target_file_join(dir, entry->d_name);
        if (path == NULL) {
            result = -1;
            break;
        }

        struct stat st;
        if (lstat(path, &st) == 0) {
            if (S_ISREG(st.st_mode)) {
                if (target_file_matches(entry->d_name, list->exts,
                                        list->ext_count) &&
                    target_file_add(list, path) != 0)
                    result = -1;
            } else if (S_ISDIR(st.st_mode)) {
                if (target_file_walk(path, list) != 0)
                    result = -1;
            }
        }

        free(path);
        if (result != 0)
            break;
    }

    closedir(stream);
    return result;
}

static char *target_file_expand_home(const char *dir)
{
    if (dir[0] != '~')
        return strdup(dir);

    const char *home = getenv("HOME");
    if (home == NULL)
        return strdup(dir);

    size_t home_len = strlen(home);
    size_t rest_len = strlen(dir + 1);
    if (home_len > SIZE_MAX - rest_len - 1)
        return NULL;

    char *expanded = malloc(home_len + rest_len + 1);
    if (expanded == NULL)
        return NULL;
    memcpy(expanded, home, home_len);
    memcpy(expanded + home_len, dir + 1, rest_len + 1);
    return expanded;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    struct target_file_list list = {
        .paths = NULL,
        .count = 0,
        .capacity = 0,
        .exts = exts,
        .ext_count = ext_count
    };

    if (dirs == NULL)
        return 0;

    for (size_t i = 0; i < dir_count; ++i) {
        if (dirs[i] == NULL)
            continue;

        char *expanded = target_file_expand_home(dirs[i]);
        if (expanded == NULL)
            goto error;

        int result = target_file_walk(expanded, &list);
        free(expanded);
        if (result != 0)
            goto error;
    }

    if (list.count == 0) {
        free(list.paths);
        return 0;
    }

    *out_paths = list.paths;
    return list.count;

error:
    for (size_t i = 0; i < list.count; ++i)
        free(list.paths[i]);
    free(list.paths);
    return 0;
}