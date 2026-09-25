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
#include <errno.h>

static int has_extension(const char *filename, const char *const *exts, size_t ext_count)
{
    size_t fn_len = strlen(filename);
    for (size_t i = 0; i < ext_count; ++i) {
        size_t ext_len = strlen(exts[i]);
        if (fn_len >= ext_len &&
            strcmp(filename + fn_len - ext_len, exts[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int add_path(char ***list, size_t *count, size_t *capacity, const char *path)
{
    if (*count >= *capacity) {
        size_t new_cap = (*capacity == 0) ? 64 : (*capacity * 2);
        char **tmp = realloc(*list, new_cap * sizeof(char *));
        if (!tmp)
            return -1;
        *list = tmp;
        *capacity = new_cap;
    }
    (*list)[*count] = strdup(path);
    if (!(*list)[*count])
        return -1;
    (*count)++;
    return 0;
}

static int walk_dir(const char *dir,
                    const char *const *exts,
                    size_t ext_count,
                    char ***list,
                    size_t *count,
                    size_t *capacity)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0;  

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        size_t dir_len = strlen(dir);
        int need_slash = (dir_len > 0 && dir[dir_len - 1] != '/');
        size_t name_len = strlen(entry->d_name);
        size_t path_len = dir_len + need_slash + name_len + 1;
        char *full_path = malloc(path_len);
        if (!full_path) {
            closedir(d);
            return -1;
        }
        strcpy(full_path, dir);
        if (need_slash)
            strcat(full_path, "/");
        strcat(full_path, entry->d_name);

        struct stat st;
        if (stat(full_path, &st) == -1) {
            free(full_path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            int r = walk_dir(full_path, exts, ext_count, list, count, capacity);
            free(full_path);
            if (r == -1) {
                closedir(d);
                return -1;
            }
        } else if (S_ISREG(st.st_mode)) {
            if (has_extension(entry->d_name, exts, ext_count)) {
                if (add_path(list, count, capacity, full_path) == -1) {
                    free(full_path);
                    closedir(d);
                    return -1;
                }
            }
            free(full_path);
        } else {
            free(full_path);
        }
    }
    closedir(d);
    return 0;
}

size_t list_target_files(const char *const *dirs,
                          size_t dir_count,
                          const char *const *exts,
                          size_t ext_count,
                          char ***out_paths)
{
    if (!out_paths)
        return 0;
    *out_paths = NULL;

    char **list = NULL;
    size_t count = 0;
    size_t capacity = 0;
    const char *home = getenv("HOME");

    for (size_t i = 0; i < dir_count; ++i) {
        const char *dir = dirs[i];
        if (!dir)
            continue;

        char *expanded = NULL;
        if (dir[0] == '~' && (dir[1] == '/' || dir[1] == '\0')) {
            if (!home)
                continue;
            size_t home_len = strlen(home);
            size_t rest_len = (dir[1] == '/' && dir[2] != '\0') ? strlen(dir + 2) : 0;
            size_t total = home_len + (dir[1] == '/' ? 1 : 0) + rest_len + 1;
            expanded = malloc(total);
            if (!expanded)
                goto error;
            strcpy(expanded, home);
            if (dir[1] == '/') {
                strcat(expanded, "/");
                strcat(expanded, dir + 2);
            }
        } else {
            expanded = strdup(dir);
            if (!expanded)
                goto error;
        }

        int r = walk_dir(expanded, exts, ext_count, &list, &count, &capacity);
        free(expanded);
        if (r == -1)
            goto error;
    }

    if (count == 0) {
        *out_paths = NULL;
        return 0;
    }

    char **result = realloc(list, (count + 1) * sizeof(char *));
    if (!result)
        goto error;
    result[count] = NULL;
    *out_paths = result;
    return count;

error:
    if (list) {
        for (size_t i = 0; i < count; ++i)
            free(list[i]);
        free(list);
    }
    *out_paths = NULL;
    return 0;
}