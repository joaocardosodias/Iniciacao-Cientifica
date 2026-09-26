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

static char *target_join_path(const char *dir, const char *name)
{
    size_t dir_len = strlen(dir);
    size_t name_len = strlen(name);
    int need_slash = dir_len != 0 && dir[dir_len - 1] != '/';
    size_t extra = (size_t)need_slash + 1;

    if (dir_len > SIZE_MAX - name_len ||
        dir_len + name_len > SIZE_MAX - extra)
        return NULL;

    char *path = malloc(dir_len + name_len + extra);
    if (path == NULL)
        return NULL;

    memcpy(path, dir, dir_len);
    size_t offset = dir_len;
    if (need_slash)
        path[offset++] = '/';
    memcpy(path + offset, name, name_len + 1);
    return path;
}

static int target_has_extension(const char *name,
                                const char *const *exts,
                                size_t ext_count)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < ext_count; ++i) {
        size_t ext_len = strlen(exts[i]);
        if (name_len >= ext_len &&
            memcmp(name + name_len - ext_len, exts[i], ext_len) == 0)
            return 1;
    }
    return 0;
}

static int target_add_path(struct target_file_list *list, const char *path)
{
    if (list->count == list->capacity) {
        size_t capacity = list->capacity == 0 ? 16 : list->capacity * 2;
        if (capacity < list->capacity ||
            capacity > SIZE_MAX / sizeof(*list->paths))
            return -1;

        char **paths = realloc(list->paths, capacity * sizeof(*paths));
        if (paths == NULL)
            return -1;
        list->paths = paths;
        list->capacity = capacity;
    }

    char *copy = strdup(path);
    if (copy == NULL)
        return -1;

    list->paths[list->count++] = copy;
    list->paths[list->count] = NULL;
    return 0;
}

static int target_walk_directory(const char *dir,
                                 const char *const *exts,
                                 size_t ext_count,
                                 struct target_file_list *list)
{
    DIR *stream = opendir(dir);
    if (stream == NULL)
        return 0;

    struct dirent *entry;
    int result = 0;

    while ((entry = readdir(stream)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *path = target_join_path(dir, entry->d_name);
        if (path == NULL) {
            result = -1;
            break;
        }

        struct stat st;
        if (lstat(path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                if (target_walk_directory(path, exts, ext_count, list) < 0)
                    result = -1;
            } else if (S_ISREG(st.st_mode) &&
                       target_has_extension(entry->d_name, exts, ext_count)) {
                if (target_add_path(list, path) < 0)
                    result = -1;
            } else if (S_ISLNK(st.st_mode) && !S_ISDIR(st.st_mode)) {
                struct stat target_st;
                if (stat(path, &target_st) == 0 &&
                    S_ISREG(target_st.st_mode) &&
                    target_has_extension(entry->d_name, exts, ext_count) &&
                    target_add_path(list, path) < 0)
                    result = -1;
            }
        }

        free(path);
        if (result < 0)
            break;
    }

    closedir(stream);
    return result;
}

static char *target_expand_home(const char *dir)
{
    if (dir[0] != '~' || (dir[1] != '\0' && dir[1] != '/'))
        return strdup(dir);

    const char *home = getenv("HOME");
    if (home == NULL)
        return strdup(dir);

    size_t home_len = strlen(home);
    size_t suffix_len = strlen(dir + 1);
    if (home_len > SIZE_MAX - suffix_len - 1)
        return NULL;

    char *expanded = malloc(home_len + suffix_len + 1);
    if (expanded == NULL)
        return NULL;

    memcpy(expanded, home, home_len);
    memcpy(expanded + home_len, dir + 1, suffix_len + 1);
    return expanded;
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

        char *dir = target_expand_home(dirs[i]);
        if (dir == NULL)
            goto error;

        int result = target_walk_directory(dir, exts, ext_count, &list);
        free(dir);
        if (result < 0)
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