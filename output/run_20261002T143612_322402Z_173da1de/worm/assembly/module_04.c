#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <limits.h>
#include <math.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <windows.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct target_file_list {
    char **paths;
    size_t count;
    size_t capacity;
    int failed;
} target_file_list;

static char *target_join_path(const char *directory, const char *name)
{
    size_t directory_length = strlen(directory);
    size_t name_length = strlen(name);
    int needs_separator =
        directory_length != 0 &&
        directory[directory_length - 1] != '\\' &&
        directory[directory_length - 1] != '/';
    size_t separator_length = needs_separator ? 1u : 0u;
    size_t total_length;
    char *path;

    if (directory_length > (size_t)-1 - separator_length ||
        directory_length + separator_length > (size_t)-1 - name_length ||
        directory_length + separator_length + name_length == (size_t)-1) {
        return NULL;
    }

    total_length = directory_length + separator_length + name_length + 1;
    path = (char *)malloc(total_length);
    if (path == NULL) {
        return NULL;
    }

    memcpy(path, directory, directory_length);
    if (needs_separator) {
        path[directory_length] = '\\';
    }
    memcpy(path + directory_length + separator_length, name, name_length + 1);
    return path;
}

static int target_file_matches_extension(const char *name,
                                         const char *const *exts,
                                         size_t ext_count)
{
    size_t name_length = strlen(name);
    size_t i;

    for (i = 0; i < ext_count; ++i) {
        size_t ext_length;

        if (exts[i] == NULL) {
            continue;
        }
        ext_length = strlen(exts[i]);
        if (ext_length <= name_length &&
            _stricmp(name + name_length - ext_length, exts[i]) == 0) {
            return 1;
        }
    }
    return 0;
}

static int target_file_list_add(target_file_list *list, const char *path)
{
    size_t length;
    char *copy;

    if (list->count > (size_t)-1 - 2) {
        list->failed = 1;
        return 0;
    }

    if (list->count + 2 > list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 16 : list->capacity;

        while (new_capacity < list->count + 2) {
            if (new_capacity > (size_t)-1 / 2) {
                new_capacity = list->count + 2;
                break;
            }
            new_capacity *= 2;
        }
        if (new_capacity > (size_t)-1 / sizeof(*list->paths)) {
            list->failed = 1;
            return 0;
        }

        char **new_paths =
            (char **)realloc(list->paths, new_capacity * sizeof(*list->paths));
        if (new_paths == NULL) {
            list->failed = 1;
            return 0;
        }
        list->paths = new_paths;
        list->capacity = new_capacity;
    }

    length = strlen(path);
    if (length == (size_t)-1) {
        list->failed = 1;
        return 0;
    }
    copy = (char *)malloc(length + 1);
    if (copy == NULL) {
        list->failed = 1;
        return 0;
    }
    memcpy(copy, path, length + 1);

    list->paths[list->count++] = copy;
    list->paths[list->count] = NULL;
    return 1;
}

static void target_walk_directory(target_file_list *list,
                                  const char *directory,
                                  const char *const *exts,
                                  size_t ext_count)
{
    char *search_path;
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle;

    if (list->failed) {
        return;
    }

    search_path = target_join_path(directory, "*");
    if (search_path == NULL) {
        list->failed = 1;
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

            child_path = target_join_path(directory, name);
            if (child_path == NULL) {
                list->failed = 1;
                break;
            }
            target_walk_directory(list, child_path, exts, ext_count);
            free(child_path);
            if (list->failed) {
                break;
            }
        } else if ((find_data.dwFileAttributes &
                    (FILE_ATTRIBUTE_DEVICE | FILE_ATTRIBUTE_REPARSE_POINT)) == 0 &&
                   target_file_matches_extension(name, exts, ext_count)) {
            char *file_path = target_join_path(directory, name);

            if (file_path == NULL) {
                list->failed = 1;
                break;
            }
            if (!target_file_list_add(list, file_path)) {
                free(file_path);
                break;
            }
            free(file_path);
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
    target_file_list list = { NULL, 0, 0, 0 };
    size_t i;

    if (out_paths == NULL) {
        return 0;
    }
    *out_paths = NULL;

    if ((dir_count != 0 && dirs == NULL) || (ext_count != 0 && exts == NULL)) {
        return 0;
    }

    for (i = 0; i < dir_count; ++i) {
        if (dirs[i] == NULL) {
            list.failed = 1;
            break;
        }
        target_walk_directory(&list, dirs[i], exts, ext_count);
        if (list.failed) {
            break;
        }
    }

    if (list.failed) {
        for (i = 0; i < list.count; ++i) {
            free(list.paths[i]);
        }
        free(list.paths);
        return 0;
    }

    if (list.count == 0) {
        free(list.paths);
        return 0;
    }

    *out_paths = list.paths;
    return list.count;
}