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
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

static int has_suffix(const char *filename, const char *const *exts, size_t ext_count)
{
    size_t len = strlen(filename);
    for (size_t i = 0; i < ext_count; ++i) {
        const char *ext = exts[i];
        size_t elen = strlen(ext);
        if (elen <= len && strcmp(filename + len - elen, ext) == 0)
            return 1;
    }
    return 0;
}

static void add_path(char ***paths, size_t *count, size_t *cap, char *new_path)
{
    if (*count == *cap) {
        size_t new_cap = *cap ? (*cap * 2) : 64;
        char **tmp = realloc(*paths, new_cap * sizeof(char *));
        if (!tmp) {
            free(new_path);
            return;
        }
        *paths = tmp;
        *cap = new_cap;
    }
    (*paths)[*count] = new_path;
    (*count)++;
}

static void walk_dir(const char *dir,
                     const char *const *exts,
                     size_t ext_count,
                     char ***paths,
                     size_t *count,
                     size_t *cap)
{
    DIR *d = opendir(dir);
    if (!d)
        return;
    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;
        char *child_path = NULL;
        if (asprintf(&child_path, "%s/%s", dir, entry->d_name) == -1)
            continue;
        struct stat st;
        if (stat(child_path, &st) == -1) {
            free(child_path);
            continue;
        }
        if (S_ISDIR(st.st_mode)) {
            walk_dir(child_path, exts, ext_count, paths, count, cap);
            free(child_path);
        } else if (S_ISREG(st.st_mode)) {
            if (has_suffix(entry->d_name, exts, ext_count)) {
                add_path(paths, count, cap, child_path);
                 
            } else {
                free(child_path);
            }
        } else {
            free(child_path);
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
    char **paths = NULL;
    size_t count = 0;
    size_t cap = 0;
    for (size_t i = 0; i < dir_count; ++i) {
        const char *dir = dirs[i];
        char *resolved = NULL;
        if (dir && dir[0] == '~') {
            const char *home = getenv("HOME");
            if (!home)
                continue;
            if (asprintf(&resolved, "%s%s", home, dir + 1) == -1)
                continue;
        } else {
            resolved = strdup(dir);
            if (!resolved)
                continue;
        }
        walk_dir(resolved, exts, ext_count, &paths, &count, &cap);
        free(resolved);
    }
    if (count == 0) {
        *out_paths = NULL;
        return 0;
    }
    char **result = malloc((count + 1) * sizeof(char *));
    if (!result) {
        for (size_t i = 0; i < count; ++i)
            free(paths[i]);
        free(paths);
        *out_paths = NULL;
        return 0;
    }
    for (size_t i = 0; i < count; ++i)
        result[i] = paths[i];
    result[count] = NULL;
    free(paths);
    *out_paths = result;
    return count;
}