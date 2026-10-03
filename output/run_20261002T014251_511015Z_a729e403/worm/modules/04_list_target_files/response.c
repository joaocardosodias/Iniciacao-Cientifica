#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char **items;
    size_t count;
    size_t capacity;
} PathList;

static int path_list_push(PathList *list, char *owned_path)
{
    char **new_items;
    size_t new_capacity;

    if (list->count == list->capacity) {
        if (list->capacity == 0) {
            new_capacity = 16;
        } else {
            if (list->capacity > SIZE_MAX / 2) {
                return 0;
            }
            new_capacity = list->capacity * 2;
        }

        if (new_capacity > SIZE_MAX / sizeof(*list->items)) {
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

    list->items[list->count++] = owned_path;
    return 1;
}

static char *path_join(const char *base, const char *name)
{
    size_t base_length;
    size_t name_length;
    size_t separator_length;
    char *result;

    if (base == NULL || name == NULL) {
        return NULL;
    }

    base_length = strlen(base);
    name_length = strlen(name);
    separator_length = 0;

    if (base_length != 0 &&
        base[base_length - 1] != '\\' &&
        base[base_length - 1] != '/') {
        separator_length = 1;
    }

    if (base_length > SIZE_MAX - separator_length ||
        base_length + separator_length > SIZE_MAX - name_length ||
        base_length + separator_length + name_length == SIZE_MAX) {
        return NULL;
    }

    result = (char *)malloc(base_length + separator_length + name_length + 1);
    if (result == NULL) {
        return NULL;
    }

    memcpy(result, base, base_length);
    if (separator_length != 0) {
        result[base_length] = '\\';
    }
    memcpy(result + base_length + separator_length, name, name_length + 1);
    return result;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    PathList pending = { NULL, 0, 0 };
    PathList files = { NULL, 0, 0 };
    size_t i;
    int failed = 0;
    char **result;

    if (out_paths == NULL) {
        return 0;
    }
    *out_paths = NULL;

    if ((dir_count != 0 && dirs == NULL) ||
        (ext_count != 0 && exts == NULL)) {
        return 0;
    }

    for (i = 0; i < dir_count; ++i) {
        size_t length;
        char *copy;

        if (dirs[i] == NULL) {
            continue;
        }

        length = strlen(dirs[i]);
        if (length == SIZE_MAX) {
            failed = 1;
            break;
        }

        copy = (char *)malloc(length + 1);
        if (copy == NULL) {
            failed = 1;
            break;
        }
        memcpy(copy, dirs[i], length + 1);

        if (!path_list_push(&pending, copy)) {
            free(copy);
            failed = 1;
            break;
        }
    }

    while (!failed && pending.count != 0) {
        char *directory = pending.items[--pending.count];
        char *search_path = path_join(directory, "*");
        WIN32_FIND_DATAA find_data;
        HANDLE find_handle;

        if (search_path == NULL) {
            free(directory);
            failed = 1;
            break;
        }

        find_handle = FindFirstFileA(search_path, &find_data);
        free(search_path);

        if (find_handle != INVALID_HANDLE_VALUE) {
            do {
                char *full_path;

                if (strcmp(find_data.cFileName, ".") == 0 ||
                    strcmp(find_data.cFileName, "..") == 0) {
                    continue;
                }

                if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                    if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
                        full_path = path_join(directory, find_data.cFileName);
                        if (full_path == NULL ||
                            !path_list_push(&pending, full_path)) {
                            free(full_path);
                            failed = 1;
                            break;
                        }
                    }
                    continue;
                }

                if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) != 0) {
                    continue;
                }

                {
                    size_t name_length = strlen(find_data.cFileName);
                    size_t ext_index;
                    int matches = 0;

                    for (ext_index = 0; ext_index < ext_count; ++ext_index) {
                        size_t ext_length;

                        if (exts[ext_index] == NULL) {
                            continue;
                        }

                        ext_length = strlen(exts[ext_index]);
                        if (ext_length <= name_length &&
                            _stricmp(find_data.cFileName + name_length - ext_length,
                                     exts[ext_index]) == 0) {
                            matches = 1;
                            break;
                        }
                    }

                    if (matches) {
                        full_path = path_join(directory, find_data.cFileName);
                        if (full_path == NULL ||
                            !path_list_push(&files, full_path)) {
                            free(full_path);
                            failed = 1;
                            break;
                        }
                    }
                }
            } while (FindNextFileA(find_handle, &find_data));

            FindClose(find_handle);
        }

        free(directory);
    }

    while (pending.count != 0) {
        free(pending.items[--pending.count]);
    }
    free(pending.items);

    if (failed || files.count == 0 ||
        files.count >= SIZE_MAX / sizeof(*result)) {
        for (i = 0; i < files.count; ++i) {
            free(files.items[i]);
        }
        free(files.items);
        return 0;
    }

    result = (char **)calloc(files.count + 1, sizeof(*result));
    if (result == NULL) {
        for (i = 0; i < files.count; ++i) {
            free(files.items[i]);
        }
        free(files.items);
        return 0;
    }

    for (i = 0; i < files.count; ++i) {
        result[i] = files.items[i];
    }

    i = files.count;
    free(files.items);
    *out_paths = result;
    return i;
}