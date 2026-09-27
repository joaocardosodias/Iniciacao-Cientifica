#define _GNU_SOURCE
#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct target_files_state {
    const char *const *exts;
    size_t ext_count;
    char **paths;
    size_t count;
    size_t capacity;
    int failed;
};

static int target_has_suffix(const char *name, const char *const *exts,
                             size_t ext_count)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < ext_count; i++) {
        if (exts[i] == NULL)
            continue;
        size_t ext_len = strlen(exts[i]);
        if (name_len >= ext_len &&
            memcmp(name + name_len - ext_len, exts[i], ext_len) == 0)
            return 1;
    }
    return 0;
}

static char *target_join_path(const char *parent, const char *name)
{
    size_t parent_len = strlen(parent);
    size_t name_len = strlen(name);
    size_t separator = parent_len != 0 && parent[parent_len - 1] != '/';

    if (parent_len > SIZE_MAX - separator ||
        parent_len + separator > SIZE_MAX - name_len ||
        parent_len + separator + name_len == SIZE_MAX)
        return NULL;

    size_t total = parent_len + separator + name_len;
    char *path = malloc(total + 1);
    if (path == NULL)
        return NULL;

    memcpy(path, parent, parent_len);
    if (separator)
        path[parent_len] = '/';
    memcpy(path + parent_len + separator, name, name_len);
    path[total] = '\0';
    return path;
}

static int target_add_path(struct target_files_state *state, const char *path)
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

    size_t len = strlen(path);
    if (len == SIZE_MAX)
        return -1;
    char *copy = malloc(len + 1);
    if (copy == NULL)
        return -1;
    memcpy(copy, path, len + 1);
    state->paths[state->count++] = copy;
    return 0;
}

static void target_walk_directory(struct target_files_state *state,
                                  const char *directory)
{
    if (state->failed)
        return;

    DIR *dir = opendir(directory);
    if (dir == NULL)
        return;

    struct dirent *entry;
    while (!state->failed && (entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *path = target_join_path(directory, entry->d_name);
        if (path == NULL) {
            state->failed = 1;
            break;
        }

        struct stat st;
        if (lstat(path, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                target_walk_directory(state, path);
            } else if (S_ISREG(st.st_mode) &&
                       target_has_suffix(entry->d_name, state->exts,
                                         state->ext_count) &&
                       target_add_path(state, path) != 0) {
                state->failed = 1;
            }
        }
        free(path);
    }

    closedir(dir);
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    if (dirs == NULL || exts == NULL || ext_count == 0)
        return 0;

    struct target_files_state state = {
        .exts = exts,
        .ext_count = ext_count,
        .paths = NULL,
        .count = 0,
        .capacity = 0,
        .failed = 0
    };

    const char *home = getenv("HOME");
    for (size_t i = 0; i < dir_count && !state.failed; i++) {
        if (dirs[i] == NULL)
            continue;

        const char *directory = dirs[i];
        char *expanded = NULL;
        if (directory[0] == '~') {
            if (home == NULL)
                continue;
            size_t home_len = strlen(home);
            size_t rest_len = strlen(directory + 1);
            if (home_len > SIZE_MAX - rest_len ||
                home_len + rest_len == SIZE_MAX) {
                state.failed = 1;
                break;
            }
            expanded = malloc(home_len + rest_len + 1);
            if (expanded == NULL) {
                state.failed = 1;
                break;
            }
            memcpy(expanded, home, home_len);
            memcpy(expanded + home_len, directory + 1, rest_len + 1);
            directory = expanded;
        }

        target_walk_directory(&state, directory);
        free(expanded);
    }

    if (state.failed) {
        for (size_t i = 0; i < state.count; i++)
            free(state.paths[i]);
        free(state.paths);
        return 0;
    }

    if (state.count == 0) {
        free(state.paths);
        return 0;
    }

    state.paths[state.count] = NULL;
    *out_paths = state.paths;
    return state.count;
}