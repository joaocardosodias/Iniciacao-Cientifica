#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct target_path_list {
    char **paths;
    size_t count;
    size_t capacity;
} target_path_list;

static char *target_join_path(const char *base, const char *leaf)
{
    size_t base_len;
    size_t leaf_len;
    size_t separator_len;
    size_t total;
    char *joined;

    base_len = strlen(base);
    leaf_len = strlen(leaf);
    separator_len = base_len != 0 &&
        base[base_len - 1] != '\\' &&
        base[base_len - 1] != '/' ? 1 : 0;

    if (base_len > (size_t)-1 - separator_len ||
        base_len + separator_len > (size_t)-1 - leaf_len ||
        base_len + separator_len + leaf_len == (size_t)-1) {
        return NULL;
    }

    total = base_len + separator_len + leaf_len + 1;
    joined = (char *)malloc(total);
    if (joined == NULL) {
        return NULL;
    }

    memcpy(joined, base, base_len);
    if (separator_len != 0) {
        joined[base_len] = '\\';
    }
    memcpy(joined + base_len + separator_len, leaf, leaf_len + 1);
    return joined;
}

static int target_has_suffix(const char *name,
                             const char *const *exts,
                             size_t ext_count)
{
    size_t name_len;
    size_t i;

    if (exts == NULL) {
        return 0;
    }

    name_len = strlen(name);
    for (i = 0; i < ext_count; ++i) {
        size_t ext_len;

        if (exts[i] == NULL) {
            continue;
        }
        ext_len = strlen(exts[i]);
        if (ext_len != 0 && ext_len <= name_len &&
            _stricmp(name + name_len - ext_len, exts[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

static int target_path_list_append(target_path_list *list, char *path)
{
    char **new_paths;
    size_t new_capacity;

    if (list->count == list->capacity) {
        if (list->capacity == 0) {
            new_capacity = 16;
        } else {
            if (list->capacity > (size_t)-1 / 2) {
                return 0;
            }
            new_capacity = list->capacity * 2;
        }

        if (new_capacity > (size_t)-1 / sizeof(*list->paths)) {
            return 0;
        }

        new_paths = (char **)realloc(list->paths,
                                     new_capacity * sizeof(*list->paths));
        if (new_paths == NULL) {
            return 0;
        }
        list->paths = new_paths;
        list->capacity = new_capacity;
    }

    list->paths[list->count++] = path;
    list->paths[list->count] = NULL;
    return 1;
}

static int target_walk_directory(const char *directory,
                                 const char *const *exts,
                                 size_t ext_count,
                                 target_path_list *list)
{
    char *pattern;
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle;
    int success;

    pattern = target_join_path(directory, "*");
    if (pattern == NULL) {
        return 0;
    }

    find_handle = FindFirstFileA(pattern, &find_data);
    free(pattern);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return 1;
    }

    success = 1;
    do {
        const char *name = find_data.cFileName;

        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
            continue;
        }

        if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
                char *child_directory = target_join_path(directory, name);
                if (child_directory == NULL) {
                    success = 0;
                    break;
                }
                if (!target_walk_directory(child_directory, exts, ext_count, list)) {
                    free(child_directory);
                    success = 0;
                    break;
                }
                free(child_directory);
            }
        } else if ((find_data.dwFileAttributes &
                    (FILE_ATTRIBUTE_REPARSE_POINT | FILE_ATTRIBUTE_DEVICE)) == 0 &&
                   target_has_suffix(name, exts, ext_count)) {
            char *file_path = target_join_path(directory, name);
            if (file_path == NULL) {
                success = 0;
                break;
            }
            if (!target_path_list_append(list, file_path)) {
                free(file_path);
                success = 0;
                break;
            }
        }
    } while (FindNextFileA(find_handle, &find_data));

    FindClose(find_handle);
    return success;
}

size_t list_target_files(const char *const *dirs,
                         size_t dir_count,
                         const char *const *exts,
                         size_t ext_count,
                         char ***out_paths)
{
    target_path_list list;
    size_t i;

    if (out_paths == NULL) {
        return 0;
    }
    *out_paths = NULL;

    list.paths = NULL;
    list.count = 0;
    list.capacity = 0;

    if (dirs == NULL) {
        return 0;
    }

    for (i = 0; i < dir_count; ++i) {
        if (dirs[i] != NULL &&
            !target_walk_directory(dirs[i], exts, ext_count, &list)) {
            size_t j;
            for (j = 0; j < list.count; ++j) {
                free(list.paths[j]);
            }
            free(list.paths);
            return 0;
        }
    }

    if (list.count == 0) {
        free(list.paths);
        return 0;
    }

    *out_paths = list.paths;
    return list.count;
}