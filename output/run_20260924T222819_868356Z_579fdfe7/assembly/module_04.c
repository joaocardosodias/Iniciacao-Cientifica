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
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>

struct path_list {
    char **items;
    size_t count;
    size_t cap;
};

static int path_list_push(struct path_list *list, const char *path)
{
    if (list->count == list->cap) {
        size_t new_cap = list->cap ? list->cap * 2 : 32;
         
        char **new_items = realloc(list->items, (new_cap + 1) * sizeof(*new_items));
        if (new_items == NULL)
            return -1;
        list->items = new_items;
        list->cap = new_cap;
    }
    char *copy = strdup(path);
    if (copy == NULL)
        return -1;
    list->items[list->count++] = copy;
    return 0;
}

static int name_matches_exts(const char *name, const char *const *exts,
                             size_t ext_count)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < ext_count; i++) {
        if (exts[i] == NULL)
            continue;
        size_t ext_len = strlen(exts[i]);
        if (ext_len <= name_len &&
            memcmp(name + name_len - ext_len, exts[i], ext_len) == 0)
            return 1;
    }
    return 0;
}

static char *expand_leading_tilde(const char *path)
{
    if (path[0] != '~')
        return strdup(path);

    const char *home = getenv("HOME");
    if (home == NULL)
        return strdup(path);

    size_t home_len = strlen(home);
    size_t rest_len = strlen(path + 1);
    char *expanded = malloc(home_len + rest_len + 1);
    if (expanded == NULL)
        return NULL;
    memcpy(expanded, home, home_len);
    memcpy(expanded + home_len, path + 1, rest_len + 1);
    return expanded;
}

static void walk_directory(const char *dir, const char *const *exts,
                           size_t ext_count, struct path_list *list)
{
    DIR *dp = opendir(dir);
    if (dp == NULL)
        return;  

    size_t dir_len = strlen(dir);
    int need_slash = dir_len > 0 && dir[dir_len - 1] != '/';

    struct dirent *ent;
    while ((ent = readdir(dp)) != NULL) {
        if (strcmp(ent->d_name, ".") == 0 || strcmp(ent->d_name, "..") == 0)
            continue;

        size_t name_len = strlen(ent->d_name);
        char *full = malloc(dir_len + (size_t)need_slash + name_len + 1);
        if (full == NULL)
            continue;
        memcpy(full, dir, dir_len);
        size_t pos = dir_len;
        if (need_slash)
            full[pos++] = '/';
        memcpy(full + pos, ent->d_name, name_len + 1);

        struct stat st;
        if (lstat(full, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                walk_directory(full, exts, ext_count, list);
            } else if (S_ISREG(st.st_mode) &&
                       name_matches_exts(ent->d_name, exts, ext_count)) {
                path_list_push(list, full);
            }
        }
        free(full);
    }

    closedir(dp);
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    if (exts == NULL)
        ext_count = 0;

    struct path_list list = { NULL, 0, 0 };

    if (dirs != NULL) {
        for (size_t i = 0; i < dir_count; i++) {
            if (dirs[i] == NULL)
                continue;
            char *root = expand_leading_tilde(dirs[i]);
            if (root == NULL)
                continue;
            walk_directory(root, exts, ext_count, &list);
            free(root);
        }
    }

    if (list.count == 0) {
        free(list.items);
        return 0;
    }

    list.items[list.count] = NULL;
    *out_paths = list.items;
    return list.count;
}