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
    size_t fname_len = strlen(filename);
    for (size_t i = 0; i < ext_count; ++i) {
        const char *ext = exts[i];
        size_t ext_len = strlen(ext);
        if (ext_len == 0)
            continue;
        if (ext_len > fname_len)
            continue;
        if (strcmp(filename + fname_len - ext_len, ext) == 0)
            return 1;
    }
    return 0;
}

 
static char *join_path(const char *dir, const char *name)
{
    size_t dir_len = strlen(dir);
    size_t name_len = strlen(name);
    int need_sep = (dir_len == 0 || dir[dir_len - 1] != '/');
    size_t total = dir_len + (need_sep ? 1 : 0) + name_len + 1;
    char *result = (char *)malloc(total);
    if (!result)
        return NULL;
    memcpy(result, dir, dir_len);
    if (need_sep) {
        result[dir_len] = '/';
        memcpy(result + dir_len + 1, name, name_len + 1);
    } else {
        memcpy(result + dir_len, name, name_len + 1);
    }
    return result;
}

 
static char *expand_tilde(const char *path)
{
    if (!path || path[0] != '~')
        return strdup(path);
    const char *home = getenv("HOME");
    if (!home)
        home = "";
    if (path[1] == '/' || path[1] == '\0') {
        const char *rest = (path[1] == '/') ? path + 2 : path + 1;
        size_t home_len = strlen(home);
        size_t rest_len = strlen(rest);
        size_t total = home_len + (rest_len ? 1 : 0) + rest_len + 1;
        char *result = (char *)malloc(total);
        if (!result)
            return NULL;
        memcpy(result, home, home_len);
        if (rest_len) {
            result[home_len] = '/';
            memcpy(result + home_len + 1, rest, rest_len + 1);
        } else {
            result[home_len] = '\0';
        }
        return result;
    }
     
    return strdup(path);
}

 
static void walk_dir(const char *dir,
                     const char *const *exts,
                     size_t ext_count,
                     char ***paths_ptr,
                     size_t *count_ptr,
                     size_t *cap_ptr)
{
    DIR *d = opendir(dir);
    if (!d)
        return;  
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        const char *name = entry->d_name;
        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;
        char *full = join_path(dir, name);
        if (!full)
            continue;
        struct stat sb;
        if (lstat(full, &sb) == -1) {
            free(full);
            continue;
        }
        if (S_ISDIR(sb.st_mode)) {
            walk_dir(full, exts, ext_count, paths_ptr, count_ptr, cap_ptr);
            free(full);
        } else if (S_ISREG(sb.st_mode)) {
            if (has_extension(name, exts, ext_count)) {
                if (*count_ptr >= *cap_ptr) {
                    size_t new_cap = (*cap_ptr == 0) ? 64 : (*cap_ptr * 2);
                    char **tmp = (char **)realloc(*paths_ptr, new_cap * sizeof(char *));
                    if (!tmp) {
                        free(full);
                        closedir(d);
                        return;
                    }
                    *paths_ptr = tmp;
                    *cap_ptr = new_cap;
                }
                (*paths_ptr)[*count_ptr] = full;  
                (*count_ptr)++;
                continue;
            }
            free(full);
        } else {
            free(full);
        }
    }
    closedir(d);
}

 
size_t list_target_files(const char *const *dirs,
                         size_t dir_count,
                         const char *const *exts,
                         size_t ext_count,
                         char ***out_paths)
{
    if (out_paths)
        *out_paths = NULL;
    if (!dirs || dir_count == 0 || !exts || ext_count == 0 || !out_paths)
        return 0;

    char **paths = NULL;
    size_t count = 0;
    size_t cap = 0;

    for (size_t i = 0; i < dir_count; ++i) {
        const char *raw_dir = dirs[i];
        if (!raw_dir)
            continue;
        char *dir = expand_tilde(raw_dir);
        if (!dir)
            continue;
        walk_dir(dir, exts, ext_count, &paths, &count, &cap);
        free(dir);
    }

    if (count == 0) {
        if (paths)
            free(paths);
        return 0;
    }

     
    if (count >= cap) {
        char **tmp = (char **)realloc(paths, (count + 1) * sizeof(char *));
        if (!tmp) {
            for (size_t i = 0; i < count; ++i)
                free(paths[i]);
            free(paths);
            return 0;
        }
        paths = tmp;
    }
    paths[count] = NULL;
    *out_paths = paths;
    return count;
}