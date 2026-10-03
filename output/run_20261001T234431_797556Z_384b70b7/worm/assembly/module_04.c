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
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

static char *list_target_files_join(const char *left, const char *right)
{
    size_t left_len = strlen(left);
    size_t right_len = strlen(right);
    size_t need_separator =
        left_len != 0 && left[left_len - 1] != '\\' && left[left_len - 1] != '/';
    size_t max_size = (size_t)-1;
    size_t total;
    char *joined;

    if (left_len > max_size - right_len ||
        left_len + right_len > max_size - need_separator ||
        left_len + right_len + need_separator == max_size) {
        return NULL;
    }

    total = left_len + right_len + need_separator + 1;
    joined = (char *)malloc(total);
    if (joined == NULL) {
        return NULL;
    }

    memcpy(joined, left, left_len);
    if (need_separator) {
        joined[left_len++] = '\\';
    }
    memcpy(joined + left_len, right, right_len);
    joined[left_len + right_len] = '\0';
    return joined;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    char **stack = NULL;
    size_t stack_count = 0;
    size_t stack_capacity = 0;
    char **paths = NULL;
    size_t path_count = 0;
    size_t path_capacity = 0;
    size_t i;
    int failed = 0;

    if (out_paths == NULL) {
        return 0;
    }
    *out_paths = NULL;

    if (dirs == NULL || exts == NULL || ext_count == 0) {
        return 0;
    }

    for (i = 0; i < dir_count; ++i) {
        const char *dir = dirs[i];
        size_t len;
        char *copy;
        char **new_stack;

        if (dir == NULL || dir[0] == '\0') {
            continue;
        }

        len = strlen(dir);
        if (len == (size_t)-1) {
            failed = 1;
            break;
        }
        copy = (char *)malloc(len + 1);
        if (copy == NULL) {
            failed = 1;
            break;
        }
        memcpy(copy, dir, len + 1);

        if (stack_count == stack_capacity) {
            size_t new_capacity = stack_capacity == 0 ? 16 : stack_capacity * 2;
            if (new_capacity < stack_capacity ||
                new_capacity > ((size_t)-1) / sizeof(*stack)) {
                free(copy);
                failed = 1;
                break;
            }
            new_stack = (char **)realloc(stack, new_capacity * sizeof(*stack));
            if (new_stack == NULL) {
                free(copy);
                failed = 1;
                break;
            }
            stack = new_stack;
            stack_capacity = new_capacity;
        }
        stack[stack_count++] = copy;
    }

    while (!failed && stack_count != 0) {
        char *current = stack[--stack_count];
        char *pattern = list_target_files_join(current, "*");
        WIN32_FIND_DATAA data;
        HANDLE find_handle;

        if (pattern == NULL) {
            free(current);
            failed = 1;
            break;
        }

        find_handle = FindFirstFileA(pattern, &data);
        if (find_handle == INVALID_HANDLE_VALUE) {
            free(pattern);
            free(current);
            continue;
        }

        do {
            const char *name = data.cFileName;
            char *full_path;

            if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
                continue;
            }

            full_path = list_target_files_join(current, name);
            if (full_path == NULL) {
                failed = 1;
                break;
            }

            if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
                if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
                    char **new_stack;

                    if (stack_count == stack_capacity) {
                        size_t new_capacity =
                            stack_capacity == 0 ? 16 : stack_capacity * 2;
                        if (new_capacity < stack_capacity ||
                            new_capacity > ((size_t)-1) / sizeof(*stack)) {
                            free(full_path);
                            failed = 1;
                            break;
                        }
                        new_stack =
                            (char **)realloc(stack, new_capacity * sizeof(*stack));
                        if (new_stack == NULL) {
                            free(full_path);
                            failed = 1;
                            break;
                        }
                        stack = new_stack;
                        stack_capacity = new_capacity;
                    }
                    stack[stack_count++] = full_path;
                } else {
                    free(full_path);
                }
            } else if ((data.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) == 0) {
                size_t name_len = strlen(name);
                int matches = 0;
                size_t ext_index;

                for (ext_index = 0; ext_index < ext_count; ++ext_index) {
                    const char *ext = exts[ext_index];
                    size_t ext_len;

                    if (ext == NULL) {
                        continue;
                    }
                    ext_len = strlen(ext);
                    if (ext_len <= name_len &&
                        _stricmp(name + name_len - ext_len, ext) == 0) {
                        matches = 1;
                        break;
                    }
                }

                if (matches) {
                    char **new_paths;

                    if (path_count == path_capacity) {
                        size_t new_capacity =
                            path_capacity == 0 ? 16 : path_capacity * 2;
                        if (new_capacity < path_capacity ||
                            new_capacity > ((size_t)-1) / sizeof(*paths) - 1) {
                            free(full_path);
                            failed = 1;
                            break;
                        }
                        new_paths = (char **)realloc(
                            paths, (new_capacity + 1) * sizeof(*paths));
                        if (new_paths == NULL) {
                            free(full_path);
                            failed = 1;
                            break;
                        }
                        paths = new_paths;
                        path_capacity = new_capacity;
                    }
                    paths[path_count++] = full_path;
                    paths[path_count] = NULL;
                } else {
                    free(full_path);
                }
            } else {
                free(full_path);
            }
        } while (FindNextFileA(find_handle, &data));

        FindClose(find_handle);
        free(pattern);
        free(current);
    }

    while (stack_count != 0) {
        free(stack[--stack_count]);
    }
    free(stack);

    if (failed) {
        for (i = 0; i < path_count; ++i) {
            free(paths[i]);
        }
        free(paths);
        return 0;
    }

    if (path_count == 0) {
        free(paths);
        return 0;
    }

    *out_paths = paths;
    return path_count;
}