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
#include <limits.h>

static int ends_with(const char *str, const char *suffix)
{
    size_t slen = strlen(str);
    size_t suflen = strlen(suffix);
    if (suflen > slen)
        return 0;
    return strcmp(str + slen - suflen, suffix) == 0;
}

static char *expand_path(const char *path)
{
    if (!path)
        return NULL;
    if (path[0] != '~')
        return strdup(path);
    const char *home = getenv("HOME");
    if (!home)
        home = "";
    if (path[1] == '/' || path[1] == '\0') {
        size_t hlen = strlen(home);
        size_t rest = strlen(path + 1);
        char *res = (char *)malloc(hlen + rest + 1);
        if (!res)
            return NULL;
        memcpy(res, home, hlen);
        memcpy(res + hlen, path + 1, rest + 1);
        return res;
    }
    return strdup(path);
}

static int add_path(char ***list, size_t *count, size_t *cap, const char *path)
{
    if (*count == *cap) {
        size_t new_cap = (*cap == 0) ? 64 : (*cap * 2);
        char **tmp = (char **)realloc(*list, new_cap * sizeof(char *));
        if (!tmp)
            return -1;
        *list = tmp;
        *cap = new_cap;
    }
    (*list)[*count] = strdup(path);
    if (!(*list)[*count])
        return -1;
    (*count)++;
    return 0;
}

static int walk_dir(const char *dir,
                    const char *const *exts, size_t ext_count,
                    char ***list, size_t *count, size_t *cap)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0;  
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        const char *name = entry->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;

        size_t dirlen = strlen(dir);
        size_t namelen = strlen(name);
        int need_sep = (dirlen > 0 && dir[dirlen - 1] != '/');
        size_t full_len = dirlen + (need_sep ? 1 : 0) + namelen;
        char *full = (char *)malloc(full_len + 1);
        if (!full) {
            closedir(d);
            return -1;
        }
        memcpy(full, dir, dirlen);
        if (need_sep)
            full[dirlen] = '/';
        memcpy(full + dirlen + (need_sep ? 1 : 0), name, namelen + 1);

        struct stat st;
        if (lstat(full, &st) == -1) {
            free(full);
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            int r = walk_dir(full, exts, ext_count, list, count, cap);
            free(full);
            if (r == -1) {
                closedir(d);
                return -1;
            }
        } else if (S_ISREG(st.st_mode)) {
            for (size_t i = 0; i < ext_count; ++i) {
                if (ends_with(name, exts[i])) {
                    if (add_path(list, count, cap, full) == -1) {
                        free(full);
                        closedir(d);
                        return -1;
                    }
                    break;
                }
            }
            free(full);
        } else {
            free(full);
        }
    }
    closedir(d);
    return 0;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    char **paths = NULL;
    size_t count = 0;
    size_t cap = 0;
    *out_paths = NULL;

    for (size_t i = 0; i < dir_count; ++i) {
        char *expanded = expand_path(dirs[i]);
        if (!expanded) {
            for (size_t j = 0; j < count; ++j)
                free(paths[j]);
            free(paths);
            return (size_t)-1;
        }
        int r = walk_dir(expanded, exts, ext_count, &paths, &count, &cap);
        free(expanded);
        if (r == -1) {
            for (size_t j = 0; j < count; ++j)
                free(paths[j]);
            free(paths);
            return (size_t)-1;
        }
    }

    if (count == 0) {
        return 0;
    }

    char **result = (char **)malloc((count + 1) * sizeof(char *));
    if (!result) {
        for (size_t j = 0; j < count; ++j)
            free(paths[j]);
        free(paths);
        return (size_t)-1;
    }
    memcpy(result, paths, count * sizeof(char *));
    result[count] = NULL;
    free(paths);
    *out_paths = result;
    return count;
}