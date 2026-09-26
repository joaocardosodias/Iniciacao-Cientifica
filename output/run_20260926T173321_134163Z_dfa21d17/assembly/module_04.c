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

static int has_extension(const char *filename, const char *const *exts, size_t ext_count) {
    const char *dot = strrchr(filename, '.');
    if (!dot) return 0;
    for (size_t i = 0; i < ext_count; ++i) {
        if (strcmp(dot + 1, exts[i]) == 0)
            return 1;
    }
    return 0;
}

static char *join_path(const char *dir, const char *name) {
    size_t len_dir = strlen(dir);
    size_t len_name = strlen(name);
    int need_sep = (len_dir == 0 || dir[len_dir - 1] != '/');
    size_t total = len_dir + need_sep + len_name + 1;
    char *res = (char *)malloc(total);
    if (!res) return NULL;
    memcpy(res, dir, len_dir);
    if (need_sep) {
        res[len_dir] = '/';
        memcpy(res + len_dir + 1, name, len_name + 1);
    } else {
        memcpy(res + len_dir, name, len_name + 1);
    }
    return res;
}

static int expand_home(const char *path, char **out) {
    if (!path || path[0] != '~')
        return 0;
    const char *home = getenv("HOME");
    if (!home) return -1;
    if (path[1] == '/' || path[1] == '\0') {
        size_t home_len = strlen(home);
        size_t rest_len = strlen(path + 1);
        *out = (char *)malloc(home_len + rest_len + 1);
        if (!*out) return -1;
        memcpy(*out, home, home_len);
        memcpy(*out + home_len, path + 1, rest_len + 1);
        return 0;
    }
    return -1;
}

static int ensure_capacity(char ***arr, size_t *cap) {
    if (*cap == 0) {
        *cap = 16;
        *arr = (char **)malloc((*cap) * sizeof(char *));
        if (!*arr) return -1;
    } else if (*cap && *arr == NULL) {
        *arr = (char **)malloc((*cap) * sizeof(char *));
        if (!*arr) return -1;
    }
    return 0;
}

static int add_path(char ***arr, size_t *cnt, size_t *cap, const char *path) {
    if (*cnt >= *cap) {
        size_t new_cap = (*cap) * 2;
        char **tmp = (char **)realloc(*arr, new_cap * sizeof(char *));
        if (!tmp) return -1;
        *arr = tmp;
        *cap = new_cap;
    }
    (*arr)[*cnt] = strdup(path);
    if (!(*arr)[*cnt]) return -1;
    (*cnt)++;
    return 0;
}

static void free_paths(char **paths, size_t cnt) {
    for (size_t i = 0; i < cnt; ++i) {
        free(paths[i]);
    }
    free(paths);
}

static int walk_dir(const char *dir, const char *const *exts, size_t ext_count,
                    char ***out_arr, size_t *out_cnt, size_t *out_cap) {
    DIR *d = opendir(dir);
    if (!d) return 0;  
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        char *full = join_path(dir, entry->d_name);
        if (!full) {
            closedir(d);
            return -1;
        }
        struct stat st;
        if (lstat(full, &st) == -1) {
            free(full);
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            int r = walk_dir(full, exts, ext_count, out_arr, out_cnt, out_cap);
            free(full);
            if (r == -1) {
                closedir(d);
                return -1;
            }
        } else if (S_ISREG(st.st_mode)) {
            if (ext_count == 0 || has_extension(entry->d_name, exts, ext_count)) {
                if (add_path(out_arr, out_cnt, out_cap, full) == -1) {
                    free(full);
                    closedir(d);
                    return -1;
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
                         char ***out_paths) {
    char **paths = NULL;
    size_t count = 0;
    size_t capacity = 0;

    for (size_t i = 0; i < dir_count; ++i) {
        const char *orig = dirs[i];
        char *expanded = NULL;
        const char *base = orig;
        if (orig && orig[0] == '~') {
            if (expand_home(orig, &expanded) != 0) {
                continue;  
            }
            base = expanded;
        }
        if (!base) continue;
        if (walk_dir(base, exts, ext_count, &paths, &count, &capacity) == -1) {
            free(expanded);
            free_paths(paths, count);
            *out_paths = NULL;
            return 0;
        }
        free(expanded);
    }

    if (count == 0) {
        *out_paths = NULL;
        return 0;
    }

     
    if (ensure_capacity(&paths, &capacity) == -1) {
        free_paths(paths, count);
        *out_paths = NULL;
        return 0;
    }
    if (count >= capacity) {
        size_t new_cap = capacity + 1;
        char **tmp = (char **)realloc(paths, new_cap * sizeof(char *));
        if (!tmp) {
            free_paths(paths, count);
            *out_paths = NULL;
            return 0;
        }
        paths = tmp;
        capacity = new_cap;
    }
    paths[count] = NULL;
    *out_paths = paths;
    return count;
}