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
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <dirent.h>

static int has_extension(const char *filename, const char *const *exts, size_t ext_count)
{
    size_t fname_len = strlen(filename);
    for (size_t i = 0; i < ext_count; ++i) {
        size_t ext_len = strlen(exts[i]);
        if (ext_len <= fname_len &&
            strcmp(filename + fname_len - ext_len, exts[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static char *make_path(const char *dir, const char *name)
{
    size_t len1 = strlen(dir);
    size_t len2 = strlen(name);
    int need_slash = (len1 == 0 || dir[len1 - 1] != '/');
    char *path = malloc(len1 + need_slash + len2 + 1);
    if (!path)
        return NULL;
    memcpy(path, dir, len1);
    if (need_slash) {
        path[len1] = '/';
        memcpy(path + len1 + 1, name, len2);
        path[len1 + 1 + len2] = '\0';
    } else {
        memcpy(path + len1, name, len2);
        path[len1 + len2] = '\0';
    }
    return path;
}

static int add_path(char ***list, size_t *capacity, size_t *count, char *path)
{
    if (*count == *capacity) {
        size_t newcap = (*capacity == 0) ? 64 : *capacity * 2;
        char **tmp = realloc(*list, newcap * sizeof(char *));
        if (!tmp)
            return -1;
        *list = tmp;
        *capacity = newcap;
    }
    (*list)[*count] = path;
    (*count)++;
    return 0;
}

static void free_paths(char **list, size_t count)
{
    for (size_t i = 0; i < count; ++i)
        free(list[i]);
    free(list);
}

static int walk_dir(const char *path, const char *const *exts, size_t ext_count,
                    char ***list, size_t *capacity, size_t *count)
{
    DIR *dir = opendir(path);
    if (!dir)
        return 0;  
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        const char *dname = entry->d_name;
        if (strcmp(dname, ".") == 0 || strcmp(dname, "..") == 0)
            continue;
        char *full = make_path(path, dname);
        if (!full) {
            closedir(dir);
            return -1;
        }
        struct stat st;
        if (stat(full, &st) == -1) {
            free(full);
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            if (walk_dir(full, exts, ext_count, list, capacity, count) == -1) {
                free(full);
                closedir(dir);
                return -1;
            }
        } else if (S_ISREG(st.st_mode)) {
            if (ext_count == 0 || has_extension(dname, exts, ext_count)) {
                if (add_path(list, capacity, count, full) == -1) {
                    free(full);
                    closedir(dir);
                    return -1;
                }
                full = NULL;
            }
        }
        if (full)
            free(full);
    }
    closedir(dir);
    return 0;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (!out_paths)
        return 0;
    *out_paths = NULL;
    char **list = NULL;
    size_t capacity = 0, count = 0;
    const char *home = getenv("HOME");
    for (size_t i = 0; i < dir_count; ++i) {
        const char *dir = dirs[i];
        if (!dir)
            continue;
        char *expanded = NULL;
        if (dir[0] == '~' && (dir[1] == '/' || dir[1] == '\0')) {
            if (!home)
                continue;
            if (dir[1] == '\0') {
                expanded = strdup(home);
            } else {
                const char *rest = dir + 2;
                size_t len_home = strlen(home);
                size_t len_rest = strlen(rest);
                expanded = malloc(len_home + 1 + len_rest + 1);
                if (!expanded) {
                    free_paths(list, count);
                    return 0;
                }
                memcpy(expanded, home, len_home);
                expanded[len_home] = '/';
                memcpy(expanded + len_home + 1, rest, len_rest);
                expanded[len_home + 1 + len_rest] = '\0';
            }
        } else {
            expanded = strdup(dir);
            if (!expanded) {
                free_paths(list, count);
                return 0;
            }
        }
        if (walk_dir(expanded, exts, ext_count, &list, &capacity, &count) == -1) {
            free(expanded);
            free_paths(list, count);
            return 0;
        }
        free(expanded);
    }
    if (count == 0) {
        free(list);
        return 0;
    }
    char **result = malloc((count + 1) * sizeof(char *));
    if (!result) {
        free_paths(list, count);
        return 0;
    }
    memcpy(result, list, count * sizeof(char *));
    result[count] = NULL;
    free(list);
    *out_paths = result;
    return count;
}