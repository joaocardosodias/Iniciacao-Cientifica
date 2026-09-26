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
#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct list_target_files_state {
    char **paths;
    size_t count;
    size_t capacity;
    const char *const *exts;
    size_t ext_count;
    int failed;
};

static int
list_target_files_matches(const char *name,
                          const char *const *exts,
                          size_t ext_count)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < ext_count; ++i) {
        if (exts[i] == NULL)
            continue;
        size_t ext_len = strlen(exts[i]);
        if (ext_len <= name_len &&
            memcmp(name + name_len - ext_len, exts[i], ext_len) == 0)
            return 1;
    }
    return 0;
}

static char *
list_target_files_join(const char *dir, const char *name)
{
    size_t dir_len = strlen(dir);
    size_t name_len = strlen(name);
    int need_slash = dir_len != 0 && dir[dir_len - 1] != '/';

    if (dir_len > SIZE_MAX - name_len - (size_t)need_slash - 1)
        return NULL;

    size_t total = dir_len + (size_t)need_slash + name_len + 1;
    char *path = malloc(total);
    if (path == NULL)
        return NULL;

    memcpy(path, dir, dir_len);
    size_t pos = dir_len;
    if (need_slash)
        path[pos++] = '/';
    memcpy(path + pos, name, name_len + 1);
    return path;
}

static int
list_target_files_add(struct list_target_files_state *state, const char *path)
{
    if (state->count == state->capacity) {
        size_t new_capacity = state->capacity == 0 ? 16 : state->capacity * 2;
        if (new_capacity < state->capacity ||
            new_capacity > SIZE_MAX / sizeof(*state->paths))
            return -1;

        char **new_paths = realloc(state->paths,
                                   new_capacity * sizeof(*state->paths));
        if (new_paths == NULL)
            return -1;
        state->paths = new_paths;
        state->capacity = new_capacity;
    }

    char *copy = strdup(path);
    if (copy == NULL)
        return -1;
    state->paths[state->count++] = copy;
    return 0;
}

static void
list_target_files_walk(const char *dir, struct list_target_files_state *state)
{
    if (state->failed)
        return;

    DIR *dp = opendir(dir);
    if (dp == NULL)
        return;

    struct dirent *entry;
    while (!state->failed && (entry = readdir(dp)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *path = list_target_files_join(dir, entry->d_name);
        if (path == NULL) {
            state->failed = 1;
            break;
        }

        struct stat st;
        if (lstat(path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                list_target_files_walk(path, state);
            } else {
                if (S_ISLNK(st.st_mode) && stat(path, &st) != 0) {
                    free(path);
                    continue;
                }
                if (S_ISREG(st.st_mode) &&
                    list_target_files_matches(entry->d_name,
                                              state->exts,
                                              state->ext_count) &&
                    list_target_files_add(state, path) != 0)
                    state->failed = 1;
            }
        }
        free(path);
    }

    closedir(dp);
}

size_t
list_target_files(const char *const *dirs, size_t dir_count,
                  const char *const *exts, size_t ext_count,
                  char ***out_paths)
{
    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    if ((dirs == NULL && dir_count != 0) ||
        (exts == NULL && ext_count != 0))
        return 0;

    struct list_target_files_state state = {
        .paths = NULL,
        .count = 0,
        .capacity = 0,
        .exts = exts,
        .ext_count = ext_count,
        .failed = 0
    };

    const char *home = getenv("HOME");
    for (size_t i = 0; i < dir_count && !state.failed; ++i) {
        if (dirs[i] == NULL)
            continue;

        const char *dir = dirs[i];
        char *expanded = NULL;
        if (dir[0] == '~' && (dir[1] == '\0' || dir[1] == '/') &&
            home != NULL) {
            size_t home_len = strlen(home);
            size_t suffix_len = strlen(dir + 1);
            if (home_len > SIZE_MAX - suffix_len - 1) {
                state.failed = 1;
                break;
            }
            expanded = malloc(home_len + suffix_len + 1);
            if (expanded == NULL) {
                state.failed = 1;
                break;
            }
            memcpy(expanded, home, home_len);
            memcpy(expanded + home_len, dir + 1, suffix_len + 1);
            dir = expanded;
        }

        list_target_files_walk(dir, &state);
        free(expanded);
    }

    if (state.failed) {
        for (size_t i = 0; i < state.count; ++i)
            free(state.paths[i]);
        free(state.paths);
        return 0;
    }

    if (state.count == 0) {
        free(state.paths);
        return 0;
    }

    char **terminated = realloc(state.paths,
                                (state.count + 1) * sizeof(*state.paths));
    if (terminated == NULL) {
        for (size_t i = 0; i < state.count; ++i)
            free(state.paths[i]);
        free(state.paths);
        return 0;
    }
    terminated[state.count] = NULL;
    *out_paths = terminated;
    return state.count;
}