#include <windows.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
    const char *const *exts;
    size_t ext_count;
} target_file_list;

static char *target_join_path(const char *dir, const char *name)
{
    size_t dir_len = strlen(dir);
    size_t name_len = strlen(name);
    int need_separator = dir_len != 0 &&
        dir[dir_len - 1] != '\\' && dir[dir_len - 1] != '/';
    size_t separator_len = need_separator ? 1 : 0;
    size_t max_size = (size_t)-1;
    char *result;

    if (dir_len > max_size - separator_len ||
        dir_len + separator_len > max_size - name_len ||
        dir_len + separator_len + name_len == max_size) {
        return NULL;
    }

    result = (char *)malloc(dir_len + separator_len + name_len + 1);
    if (result == NULL) {
        return NULL;
    }

    memcpy(result, dir, dir_len);
    if (need_separator) {
        result[dir_len] = '\\';
    }
    memcpy(result + dir_len + separator_len, name, name_len + 1);
    return result;
}

static int target_file_matches_extension(const char *name,
                                         const target_file_list *list)
{
    size_t name_len = strlen(name);
    size_t i;

    for (i = 0; i < list->ext_count; ++i) {
        const char *ext = list->exts[i];
        size_t ext_len;

        if (ext == NULL) {
            continue;
        }
        ext_len = strlen(ext);
        if (ext_len != 0 && ext_len <= name_len &&
            _stricmp(name + name_len - ext_len, ext) == 0) {
            return 1;
        }
    }

    return 0;
}

static int target_file_list_add(target_file_list *list, char *path)
{
    size_t max_size = (size_t)-1;
    size_t needed;
    size_t new_capacity;
    char **new_items;

    if (list->count > max_size - 2) {
        return 0;
    }
    needed = list->count + 2;

    if (list->capacity < needed) {
        new_capacity = list->capacity != 0 ? list->capacity : 16;
        while (new_capacity < needed) {
            if (new_capacity > max_size / 2) {
                return 0;
            }
            new_capacity *= 2;
        }
        if (new_capacity > max_size / sizeof(*list->items)) {
            return 0;
        }

        new_items = (char **)realloc(list->items,
                                     new_capacity * sizeof(*list->items));
        if (new_items == NULL) {
            return 0;
        }
        list->items = new_items;
        list->capacity = new_capacity;
    }

    list->items[list->count++] = path;
    list->items[list->count] = NULL;
    return 1;
}

static int target_walk_directory(const char *dir, target_file_list *list)
{
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle;
    char *search_path = target_join_path(dir, "*");
    int result = 1;

    if (search_path == NULL) {
        return 0;
    }

    find_handle = FindFirstFileA(search_path, &find_data);
    free(search_path);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return 1;
    }

    do {
        char *full_path;

        if (strcmp(find_data.cFileName, ".") == 0 ||
            strcmp(find_data.cFileName, "..") == 0) {
            continue;
        }

        if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                continue;
            }

            full_path = target_join_path(dir, find_data.cFileName);
            if (full_path == NULL) {
                result = 0;
                break;
            }
            if (!target_walk_directory(full_path, list)) {
                free(full_path);
                result = 0;
                break;
            }
            free(full_path);
        } else if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) == 0 &&
                   target_file_matches_extension(find_data.cFileName, list)) {
            full_path = target_join_path(dir, find_data.cFileName);
            if (full_path == NULL) {
                result = 0;
                break;
            }
            if (!target_file_list_add(list, full_path)) {
                free(full_path);
                result = 0;
                break;
            }
        }
    } while (FindNextFileA(find_handle, &find_data));

    FindClose(find_handle);
    return result;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    target_file_list list;
    char **result;
    size_t i;

    if (out_paths == NULL) {
        return 0;
    }
    *out_paths = NULL;

    if ((dir_count != 0 && dirs == NULL) ||
        (ext_count != 0 && exts == NULL)) {
        return 0;
    }

    memset(&list, 0, sizeof(list));
    list.exts = exts;
    list.ext_count = ext_count;

    for (i = 0; i < dir_count; ++i) {
        if (dirs[i] != NULL && !target_walk_directory(dirs[i], &list)) {
            size_t j;
            for (j = 0; j < list.count; ++j) {
                free(list.items[j]);
            }
            free(list.items);
            return 0;
        }
    }

    if (list.count == 0) {
        free(list.items);
        return 0;
    }

    if (list.count > ((size_t)-1) / sizeof(*result) - 1) {
        for (i = 0; i < list.count; ++i) {
            free(list.items[i]);
        }
        free(list.items);
        return 0;
    }

    result = (char **)malloc((list.count + 1) * sizeof(*result));
    if (result == NULL) {
        for (i = 0; i < list.count; ++i) {
            free(list.items[i]);
        }
        free(list.items);
        return 0;
    }

    memcpy(result, list.items, list.count * sizeof(*result));
    result[list.count] = NULL;
    free(list.items);
    *out_paths = result;
    return list.count;
}