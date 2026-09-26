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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static int
has_matching_extension(const char *name, const char *const *exts, size_t ext_count)
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

static char *
join_path(const char *directory, const char *name)
{
    size_t dir_len = strlen(directory);
    int needs_slash = dir_len != 0 && directory[dir_len - 1] != '/';
    char *path = NULL;

    if (asprintf(&path, needs_slash ? "%s/%s" : "%s%s",
                 directory, name) < 0)
        return NULL;
    return path;
}

static int
append_path(char ***paths, size_t *count, size_t *capacity, const char *path)
{
    if (*count + 1 >= *capacity) {
        size_t new_capacity = *capacity == 0 ? 16 : *capacity * 2;
        if (new_capacity < *capacity ||
            new_capacity > SIZE_MAX / sizeof(**paths))
            return -1;

        char **new_paths = realloc(*paths, new_capacity * sizeof(**paths));
        if (new_paths == NULL)
            return -1;
        *paths = new_paths;
        *capacity = new_capacity;
    }

    char *copy = strdup(path);
    if (copy == NULL)
        return -1;

    (*paths)[(*count)++] = copy;
    (*paths)[*count] = NULL;
    return 0;
}

static int
walk_directory(const char *directory,
               const char *const *exts,
               size_t ext_count,
               char ***paths,
               size_t *count,
               size_t *capacity)
{
    DIR *dir = opendir(directory);
    if (dir == NULL)
        return 0;

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *path = join_path(directory, entry->d_name);
        if (path == NULL) {
            closedir(dir);
            return -1;
        }

        struct stat lst;
        if (lstat(path, &lst) == 0) {
            if (S_ISDIR(lst.st_mode)) {
                if (walk_directory(path, exts, ext_count,
                                   paths, count, capacity) < 0) {
                    free(path);
                    closedir(dir);
                    return -1;
                }
            } else if (has_matching_extension(entry->d_name, exts, ext_count)) {
                struct stat st;
                if ((S_ISREG(lst.st_mode) ||
                     (S_ISLNK(lst.st_mode) && stat(path, &st) == 0 &&
                      S_ISREG(st.st_mode))) &&
                    append_path(paths, count, capacity, path) < 0) {
                    free(path);
                    closedir(dir);
                    return -1;
                }
            }
        }

        free(path);
    }

    closedir(dir);
    return 0;
}

size_t
list_target_files(const char *const *dirs, size_t dir_count,
                  const char *const *exts, size_t ext_count,
                  char ***out_paths)
{
    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    if (dirs == NULL)
        return 0;

    char **paths = NULL;
    size_t count = 0;
    size_t capacity = 0;

    for (size_t i = 0; i < dir_count; ++i) {
        if (dirs[i] == NULL)
            continue;

        const char *directory = dirs[i];
        char *expanded = NULL;

        if (directory[0] == '~' &&
            (directory[1] == '\0' || directory[1] == '/')) {
            const char *home = getenv("HOME");
            if (home == NULL)
                continue;
            if (asprintf(&expanded, "%s%s", home, directory + 1) < 0) {
                for (size_t j = 0; j < count; ++j)
                    free(paths[j]);
                free(paths);
                return 0;
            }
            directory = expanded;
        }

        int result = walk_directory(directory, exts, ext_count,
                                    &paths, &count, &capacity);
        free(expanded);

        if (result < 0) {
            for (size_t j = 0; j < count; ++j)
                free(paths[j]);
            free(paths);
            return 0;
        }
    }

    if (count == 0) {
        free(paths);
        return 0;
    }

    *out_paths = paths;
    return count;
}