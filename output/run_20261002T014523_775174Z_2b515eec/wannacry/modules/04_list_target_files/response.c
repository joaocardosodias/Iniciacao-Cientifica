#include <windows.h>
#include <stdlib.h>
#include <string.h>

typedef struct list_target_files_state {
    char **paths;
    size_t count;
    size_t capacity;
    const char *const *exts;
    size_t ext_count;
    int failed;
} list_target_files_state;

static char *list_target_files_join_path(const char *base, const char *tail)
{
    size_t base_len = strlen(base);
    size_t tail_len = strlen(tail);
    int has_separator = base_len != 0 &&
        (base[base_len - 1] == '\\' || base[base_len - 1] == '/');
    int drive_relative = base_len == 2 && base[1] == ':';
    size_t separator_len = (has_separator || drive_relative) ? 0 : 1;
    size_t max_size = (size_t)-1;
    size_t total;
    char *result;

    if (base_len > max_size - separator_len - 1 ||
        tail_len > max_size - base_len - separator_len - 1) {
        return NULL;
    }

    total = base_len + separator_len + tail_len + 1;
    result = (char *)malloc(total);
    if (result == NULL) {
        return NULL;
    }

    memcpy(result, base, base_len);
    if (separator_len != 0) {
        result[base_len++] = '\\';
    }
    memcpy(result + base_len, tail, tail_len);
    result[base_len + tail_len] = '\0';
    return result;
}

static int list_target_files_matches_extension(
    const char *name,
    const char *const *exts,
    size_t ext_count)
{
    size_t name_len = strlen(name);
    size_t i;

    for (i = 0; i < ext_count; ++i) {
        const char *ext = exts[i];
        size_t ext_len;

        if (ext == NULL) {
            continue;
        }
        ext_len = strlen(ext);
        if (ext_len <= name_len &&
            _stricmp(name + name_len - ext_len, ext) == 0) {
            return 1;
        }
    }
    return 0;
}

static int list_target_files_append(
    list_target_files_state *state,
    char *path)
{
    size_t needed;
    size_t new_capacity;
    char **new_paths;

    if (state->count > (size_t)-1 - 2) {
        free(path);
        state->failed = 1;
        return 0;
    }
    needed = state->count + 2;

    if (state->capacity < needed) {
        new_capacity = state->capacity == 0 ? 16 : state->capacity;
        while (new_capacity < needed) {
            if (new_capacity > (size_t)-1 / 2) {
                new_capacity = needed;
                break;
            }
            new_capacity *= 2;
        }
        if (new_capacity > (size_t)-1 / sizeof(*state->paths)) {
            free(path);
            state->failed = 1;
            return 0;
        }

        if (state->paths == NULL) {
            new_paths = (char **)calloc(new_capacity, sizeof(*state->paths));
        } else {
            new_paths = (char **)realloc(
                state->paths, new_capacity * sizeof(*state->paths));
        }
        if (new_paths == NULL) {
            free(path);
            state->failed = 1;
            return 0;
        }
        state->paths = new_paths;
        state->capacity = new_capacity;
    }

    state->paths[state->count++] = path;
    state->paths[state->count] = NULL;
    return 1;
}

static void list_target_files_walk(
    list_target_files_state *state,
    const char *directory)
{
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle;
    char *search_path;

    if (state->failed) {
        return;
    }

    search_path = list_target_files_join_path(directory, "*");
    if (search_path == NULL) {
        state->failed = 1;
        return;
    }

    find_handle = FindFirstFileA(search_path, &find_data);
    free(search_path);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        const char *name = find_data.cFileName;

        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }

        if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            char *child_path;

            if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                continue;
            }

            child_path = list_target_files_join_path(directory, name);
            if (child_path == NULL) {
                state->failed = 1;
                break;
            }
            list_target_files_walk(state, child_path);
            free(child_path);
            if (state->failed) {
                break;
            }
        } else if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) == 0 &&
                   list_target_files_matches_extension(
                       name, state->exts, state->ext_count)) {
            char *file_path = list_target_files_join_path(directory, name);

            if (file_path == NULL ||
                !list_target_files_append(state, file_path)) {
                if (file_path == NULL) {
                    state->failed = 1;
                }
                break;
            }
        }
    } while (FindNextFileA(find_handle, &find_data));

    FindClose(find_handle);
}

size_t list_target_files(
    const char *const *dirs,
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

    if ((dir_count != 0 && dirs == NULL) ||
        (ext_count != 0 && exts == NULL)) {
        return 0;
    }

    memset(&state, 0, sizeof(state));
    state.exts = exts;
    state.ext_count = ext_count;

    for (i = 0; i < dir_count && !state.failed; ++i) {
        const char *directory;

        if (dirs[i] == NULL) {
            continue;
        }
        directory = dirs[i][0] == '\0' ? "." : dirs[i];
        list_target_files_walk(&state, directory);
    }

    if (state.failed) {
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