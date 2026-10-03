#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stddef.h>

typedef struct list_target_files_state {
    const char *const *exts;
    size_t ext_count;
    char **paths;
    size_t count;
    size_t capacity;
    int allocation_failed;
} list_target_files_state;

static char *list_target_files_join(const char *base, const char *name)
{
    size_t base_len = strlen(base);
    size_t name_len = strlen(name);
    size_t separator = base_len != 0 &&
        base[base_len - 1] != '\\' && base[base_len - 1] != '/' ? 1 : 0;
    size_t limit = (size_t)-1;
    size_t total;
    char *result;

    if (base_len > limit - separator ||
        base_len + separator > limit - name_len ||
        base_len + separator + name_len == limit) {
        return NULL;
    }

    total = base_len + separator + name_len + 1;
    result = (char *)malloc(total);
    if (result == NULL) {
        return NULL;
    }

    memcpy(result, base, base_len);
    if (separator) {
        result[base_len] = '\\';
    }
    memcpy(result + base_len + separator, name, name_len + 1);
    return result;
}

static char *list_target_files_search_pattern(const char *directory)
{
    size_t directory_len = strlen(directory);
    size_t separator = directory_len != 0 &&
        directory[directory_len - 1] != '\\' &&
        directory[directory_len - 1] != '/' ? 1 : 0;
    size_t limit = (size_t)-1;
    size_t total;
    char *pattern;

    if (directory_len > limit - separator ||
        directory_len + separator > limit - 2) {
        return NULL;
    }

    total = directory_len + separator + 2;
    pattern = (char *)malloc(total);
    if (pattern == NULL) {
        return NULL;
    }

    memcpy(pattern, directory, directory_len);
    if (separator) {
        pattern[directory_len] = '\\';
    }
    pattern[directory_len + separator] = '*';
    pattern[directory_len + separator + 1] = '\0';
    return pattern;
}

static int list_target_files_matches_extension(
    const char *name,
    const char *const *exts,
    size_t ext_count)
{
    size_t name_len = strlen(name);
    size_t i;

    for (i = 0; i < ext_count; ++i) {
        size_t ext_len;

        if (exts[i] == NULL) {
            continue;
        }
        ext_len = strlen(exts[i]);
        if (ext_len != 0 && name_len >= ext_len &&
            _stricmp(name + name_len - ext_len, exts[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int list_target_files_append(list_target_files_state *state,
                                    const char *path)
{
    char *copy;
    char **new_paths;
    size_t new_capacity;

    if (state->count > (size_t)-1 - 2) {
        state->allocation_failed = 1;
        return 0;
    }

    copy = (char *)malloc(strlen(path) + 1);
    if (copy == NULL) {
        state->allocation_failed = 1;
        return 0;
    }
    strcpy(copy, path);

    if (state->count + 1 >= state->capacity) {
        if (state->capacity == 0) {
            new_capacity = 8;
        } else {
            if (state->capacity > (size_t)-1 / 2) {
                free(copy);
                state->allocation_failed = 1;
                return 0;
            }
            new_capacity = state->capacity * 2;
        }

        if (new_capacity < state->count + 2 ||
            new_capacity > (size_t)-1 / sizeof(*state->paths)) {
            free(copy);
            state->allocation_failed = 1;
            return 0;
        }

        new_paths = (char **)realloc(state->paths,
                                     new_capacity * sizeof(*state->paths));
        if (new_paths == NULL) {
            free(copy);
            state->allocation_failed = 1;
            return 0;
        }
        state->paths = new_paths;
        state->capacity = new_capacity;
    }

    state->paths[state->count++] = copy;
    state->paths[state->count] = NULL;
    return 1;
}

static void list_target_files_walk(const char *directory,
                                   list_target_files_state *state)
{
    char *pattern;
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle;

    if (state->allocation_failed) {
        return;
    }

    pattern = list_target_files_search_pattern(directory);
    if (pattern == NULL) {
        state->allocation_failed = 1;
        return;
    }

    find_handle = FindFirstFileA(pattern, &find_data);
    free(pattern);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        char *child_path;

        if (strcmp(find_data.cFileName, ".") == 0 ||
            strcmp(find_data.cFileName, "..") == 0) {
            continue;
        }

        child_path = list_target_files_join(directory, find_data.cFileName);
        if (child_path == NULL) {
            state->allocation_failed = 1;
            break;
        }

        if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
                list_target_files_walk(child_path, state);
            }
        } else if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) == 0 &&
                   list_target_files_matches_extension(find_data.cFileName,
                                                       state->exts,
                                                       state->ext_count)) {
            list_target_files_append(state, child_path);
        }

        free(child_path);
        if (state->allocation_failed) {
            break;
        }
    } while (FindNextFileA(find_handle, &find_data));

    FindClose(find_handle);
}

size_t list_target_files(const char *const *dirs,
                         size_t dir_count,
                         const char *const *exts,
                         size_t ext_count,
                         char ***out_paths)
{
    list_target_files_state state;
    size_t i;

    if (out_paths == NULL) {
        return 0;
    }
    *out_paths = NULL;

    memset(&state, 0, sizeof(state));
    state.exts = exts;
    state.ext_count = exts != NULL ? ext_count : 0;

    if (dirs != NULL) {
        for (i = 0; i < dir_count && !state.allocation_failed; ++i) {
            if (dirs[i] != NULL) {
                list_target_files_walk(dirs[i], &state);
            }
        }
    }

    if (state.allocation_failed) {
        for (i = 0; i < state.count; ++i) {
            free(state.paths[i]);
        }
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