#define _GNU_SOURCE
#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct path_list_state {
    char **paths;
    size_t count;
    size_t capacity;
    int failed;
};

static char *join_path(const char *directory, const char *name)
{
    size_t directory_length = strlen(directory);
    size_t name_length = strlen(name);
    int needs_separator = directory_length != 0 &&
                          directory[directory_length - 1] != '/';
    size_t separator_length = (size_t)needs_separator;
    char *result;

    if (name_length > SIZE_MAX - separator_length - 1 ||
        directory_length > SIZE_MAX - name_length - separator_length - 1)
        return NULL;

    result = malloc(directory_length + separator_length + name_length + 1);
    if (result == NULL)
        return NULL;

    memcpy(result, directory, directory_length);
    if (needs_separator)
        result[directory_length] = '/';
    memcpy(result + directory_length + separator_length, name, name_length + 1);
    return result;
}

static int has_target_suffix(const char *filename,
                             const char *const *extensions,
                             size_t extension_count)
{
    size_t filename_length = strlen(filename);
    size_t i;

    for (i = 0; i < extension_count; i++) {
        size_t extension_length;

        if (extensions[i] == NULL)
            continue;
        extension_length = strlen(extensions[i]);
        if (extension_length <= filename_length &&
            memcmp(filename + filename_length - extension_length,
                   extensions[i], extension_length) == 0)
            return 1;
    }
    return 0;
}

static int append_path(struct path_list_state *state, char *path)
{
    if (state->count > SIZE_MAX - 2) {
        state->failed = 1;
        return -1;
    }

    if (state->count + 2 > state->capacity) {
        size_t new_capacity = state->capacity == 0 ? 16 : state->capacity;
        char **new_paths;

        while (new_capacity < state->count + 2) {
            if (new_capacity > SIZE_MAX / 2) {
                new_capacity = state->count + 2;
                break;
            }
            new_capacity *= 2;
        }
        if (new_capacity > SIZE_MAX / sizeof(*new_paths)) {
            state->failed = 1;
            return -1;
        }

        new_paths = realloc(state->paths, new_capacity * sizeof(*new_paths));
        if (new_paths == NULL) {
            state->failed = 1;
            return -1;
        }
        state->paths = new_paths;
        state->capacity = new_capacity;
    }

    state->paths[state->count++] = path;
    state->paths[state->count] = NULL;
    return 0;
}

static void walk_target_directory(const char *directory,
                                 const char *const *extensions,
                                 size_t extension_count,
                                 struct path_list_state *state)
{
    DIR *dir;
    struct dirent *entry;

    if (state->failed)
        return;

    dir = opendir(directory);
    if (dir == NULL)
        return;

    while (!state->failed && (entry = readdir(dir)) != NULL) {
        char *path;
        struct stat info;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        path = join_path(directory, entry->d_name);
        if (path == NULL) {
            state->failed = 1;
            break;
        }

        if (lstat(path, &info) != 0) {
            free(path);
            continue;
        }

        if (S_ISDIR(info.st_mode)) {
            walk_target_directory(path, extensions, extension_count, state);
            free(path);
        } else if (S_ISREG(info.st_mode) &&
                   has_target_suffix(entry->d_name, extensions, extension_count)) {
            if (append_path(state, path) != 0)
                free(path);
        } else {
            free(path);
        }
    }

    closedir(dir);
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    struct path_list_state state = { NULL, 0, 0, 0 };
    const char *home = getenv("HOME");
    size_t i;

    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    if (dirs == NULL)
        return 0;

    for (i = 0; i < dir_count && !state.failed; i++) {
        const char *directory = dirs[i];
        char *expanded = NULL;

        if (directory == NULL)
            continue;

        if (directory[0] == '~' &&
            (directory[1] == '\0' || directory[1] == '/') &&
            home != NULL && home[0] != '\0') {
            expanded = join_path(home, directory[1] == '/' ? directory + 2 : "");
            if (expanded == NULL) {
                state.failed = 1;
                break;
            }
            directory = expanded;
        }

        walk_target_directory(directory, exts, ext_count, &state);
        free(expanded);
    }

    if (state.failed) {
        for (i = 0; i < state.count; i++)
            free(state.paths[i]);
        free(state.paths);
        return 0;
    }

    if (state.count == 0) {
        free(state.paths);
        return 0;
    }

    *out_paths = state.paths;
    return state.count;
}