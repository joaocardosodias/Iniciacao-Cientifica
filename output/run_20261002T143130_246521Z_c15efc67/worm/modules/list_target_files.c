#include <windows.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

typedef struct {
    const char *const *exts;
    size_t ext_count;
    char **paths;
    size_t count;
    size_t capacity;
} list_target_files_state;

static char *list_target_files_join(const char *directory, const char *name)
{
    size_t directory_length = strlen(directory);
    size_t name_length = strlen(name);
    int needs_separator;
    size_t total_length;
    char *result;

    needs_separator = directory_length != 0 &&
        directory[directory_length - 1] != '\\' &&
        directory[directory_length - 1] != '/';

    if (directory_length > (size_t)-1 - name_length - (size_t)needs_separator - 1)
        return NULL;

    total_length = directory_length + (size_t)needs_separator + name_length + 1;
    result = (char *)malloc(total_length);
    if (result == NULL)
        return NULL;

    memcpy(result, directory, directory_length);
    if (needs_separator)
        result[directory_length++] = '\\';
    memcpy(result + directory_length, name, name_length + 1);
    return result;
}

static int list_target_files_matches(const char *name,
                                     const char *const *exts,
                                     size_t ext_count)
{
    size_t name_length = strlen(name);
    size_t i;

    for (i = 0; i < ext_count; ++i) {
        size_t ext_length;

        if (exts[i] == NULL)
            continue;

        ext_length = strlen(exts[i]);
        if (ext_length != 0 && name_length >= ext_length &&
            _strnicmp(name + name_length - ext_length, exts[i], ext_length) == 0)
            return 1;
    }

    return 0;
}

static int list_target_files_append(list_target_files_state *state, const char *path)
{
    size_t path_length = strlen(path);
    char *copy;

    if (state->count == (size_t)-1)
        return 0;

    if (state->count + 1 >= state->capacity) {
        size_t new_capacity;
        char **new_paths;

        if (state->capacity == 0) {
            new_capacity = 16;
        } else {
            if (state->capacity > (size_t)-1 / 2)
                return 0;
            new_capacity = state->capacity * 2;
        }

        if (new_capacity > (size_t)-1 / sizeof(*state->paths))
            return 0;

        new_paths = (char **)realloc(state->paths, new_capacity * sizeof(*state->paths));
        if (new_paths == NULL)
            return 0;

        state->paths = new_paths;
        state->capacity = new_capacity;
    }

    if (path_length == (size_t)-1)
        return 0;

    copy = (char *)malloc(path_length + 1);
    if (copy == NULL)
        return 0;
    memcpy(copy, path, path_length + 1);

    state->paths[state->count++] = copy;
    state->paths[state->count] = NULL;
    return 1;
}

static int list_target_files_walk(const char *directory,
                                  list_target_files_state *state)
{
    char *search_path;
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle;
    BOOL has_entry;

    search_path = list_target_files_join(directory, "*");
    if (search_path == NULL)
        return 0;

    find_handle = FindFirstFileA(search_path, &find_data);
    free(search_path);
    if (find_handle == INVALID_HANDLE_VALUE) {
        DWORD error = GetLastError();
        return error == ERROR_FILE_NOT_FOUND || error == ERROR_PATH_NOT_FOUND;
    }

    has_entry = TRUE;
    while (has_entry) {
        if (strcmp(find_data.cFileName, ".") != 0 &&
            strcmp(find_data.cFileName, "..") != 0) {
            char *entry_path = list_target_files_join(directory, find_data.cFileName);

            if (entry_path == NULL) {
                FindClose(find_handle);
                return 0;
            }

            if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0 &&
                    !list_target_files_walk(entry_path, state)) {
                    free(entry_path);
                    FindClose(find_handle);
                    return 0;
                }
            } else if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) == 0 &&
                       list_target_files_matches(find_data.cFileName,
                                                 state->exts,
                                                 state->ext_count)) {
                if (!list_target_files_append(state, entry_path)) {
                    free(entry_path);
                    FindClose(find_handle);
                    return 0;
                }
            }

            free(entry_path);
        }

        has_entry = FindNextFileA(find_handle, &find_data);
        if (!has_entry && GetLastError() != ERROR_NO_MORE_FILES) {
            FindClose(find_handle);
            return 0;
        }
    }

    FindClose(find_handle);
    return 1;
}

size_t list_target_files(const char *const *dirs,
                         size_t dir_count,
                         const char *const *exts,
                         size_t ext_count,
                         char ***out_paths)
{
    list_target_files_state state;
    size_t i;

    if (out_paths == NULL)
        return (size_t)-1;

    *out_paths = NULL;

    if ((dir_count != 0 && dirs == NULL) ||
        (ext_count != 0 && exts == NULL))
        return (size_t)-1;

    state.exts = exts;
    state.ext_count = ext_count;
    state.paths = NULL;
    state.count = 0;
    state.capacity = 0;

    for (i = 0; i < dir_count; ++i) {
        if (dirs[i] != NULL && dirs[i][0] != '\0' &&
            !list_target_files_walk(dirs[i], &state)) {
            size_t j;
            for (j = 0; j < state.count; ++j)
                free(state.paths[j]);
            free(state.paths);
            return (size_t)-1;
        }
    }

    if (state.count == 0) {
        free(state.paths);
        return 0;
    }

    *out_paths = state.paths;
    return state.count;
}