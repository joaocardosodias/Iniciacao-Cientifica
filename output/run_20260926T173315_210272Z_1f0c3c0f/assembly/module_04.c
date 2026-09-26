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
#include <dirent.h>
#include <errno.h>
#include <unistd.h>

static char *expand_tilde(const char *path)
{
    if (!path || path[0] != '~')
        return strdup(path);
    const char *home = getenv("HOME");
    if (!home)
        home = "";
    if (path[1] == '/' || path[1] == '\0') {
        size_t home_len = strlen(home);
        size_t rest_len = strlen(path + 1);
        char *res = (char *)malloc(home_len + rest_len + 1);
        if (!res)
            return NULL;
        memcpy(res, home, home_len);
        memcpy(res + home_len, path + 1, rest_len + 1);
        return res;
    }
     
    return strdup(path);
}

static char *join_path(const char *dir, const char *name)
{
    size_t dlen = strlen(dir);
    size_t nlen = strlen(name);
    int need_sep = (dlen == 0 || dir[dlen - 1] != '/');
    size_t total = dlen + need_sep + nlen + 1;
    char *res = (char *)malloc(total);
    if (!res)
        return NULL;
    memcpy(res, dir, dlen);
    if (need_sep) {
        res[dlen] = '/';
        memcpy(res + dlen + 1, name, nlen + 1);
    } else {
        memcpy(res + dlen, name, nlen + 1);
    }
    return res;
}

static int has_matching_ext(const char *name, const char *const *exts, size_t ext_count)
{
    size_t namelen = strlen(name);
    for (size_t i = 0; i < ext_count; ++i) {
        const char *ext = exts[i];
        size_t elen = strlen(ext);
        if (elen == 0)
            continue;
        if (namelen >= elen && memcmp(name + namelen - elen, ext, elen) == 0)
            return 1;
    }
    return 0;
}

static int add_path(char ***array, size_t *count, size_t *capacity, const char *path)
{
    if (*count == *capacity) {
        size_t new_cap = (*capacity == 0) ? 64 : (*capacity * 2);
        char **tmp = (char **)realloc(*array, new_cap * sizeof(char *));
        if (!tmp)
            return -1;
        *array = tmp;
        *capacity = new_cap;
    }
    (*array)[*count] = strdup(path);
    if (!(*array)[*count])
        return -1;
    (*count)++;
    return 0;
}

static int walk_dir(const char *dir,
                    const char *const *exts,
                    size_t ext_count,
                    char ***array,
                    size_t *count,
                    size_t *capacity)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0;  
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        const char *d_name = entry->d_name;
        if (strcmp(d_name, ".") == 0 || strcmp(d_name, "..") == 0)
            continue;
        char *fullpath = join_path(dir, d_name);
        if (!fullpath) {
            closedir(d);
            return -1;
        }
        struct stat st;
        if (lstat(fullpath, &st) == -1) {
            free(fullpath);
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
             
            if (!S_ISLNK(st.st_mode)) {
                if (walk_dir(fullpath, exts, ext_count, array, count, capacity) == -1) {
                    free(fullpath);
                    closedir(d);
                    return -1;
                }
            }
        } else if (S_ISREG(st.st_mode)) {
            if (has_matching_ext(d_name, exts, ext_count)) {
                if (add_path(array, count, capacity, fullpath) == -1) {
                    free(fullpath);
                    closedir(d);
                    return -1;
                }
            }
        }
        free(fullpath);
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
    if (!out_paths) {
        return 0;
    }
    *out_paths = NULL;
    char **paths = NULL;
    size_t count = 0;
    size_t capacity = 0;
    for (size_t i = 0; i < dir_count; ++i) {
        char *expanded = expand_tilde(dirs[i]);
        if (!expanded) {
            goto error;
        }
        if (walk_dir(expanded, exts, ext_count, &paths, &count, &capacity) == -1) {
            free(expanded);
            goto error;
        }
        free(expanded);
    }
    if (count == 0) {
        *out_paths = NULL;
        return 0;
    }
     
    char **tmp = (char **)realloc(paths, (count + 1) * sizeof(char *));
    if (!tmp) {
        goto error;
    }
    paths = tmp;
    paths[count] = NULL;
    *out_paths = paths;
    return count;

error:
    if (paths) {
        for (size_t i = 0; i < count; ++i) {
            free(paths[i]);
        }
        free(paths);
    }
    *out_paths = NULL;
    return 0;
}