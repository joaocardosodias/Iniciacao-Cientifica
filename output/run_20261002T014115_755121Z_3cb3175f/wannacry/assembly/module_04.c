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

typedef struct LTF_CONTEXT {
    char **paths;
    size_t count;
    size_t capacity;
    int allocation_failed;
} LTF_CONTEXT;

static char *ltf_join_path(const char *directory, const char *name)
{
    size_t directory_length;
    size_t name_length;
    size_t separator_length;
    size_t total_length;
    char *result;

    directory_length = strlen(directory);
    name_length = strlen(name);
    separator_length = directory_length != 0 &&
        directory[directory_length - 1] != '\\' &&
        directory[directory_length - 1] != '/' ? 1 : 0;

    if (directory_length > (size_t)-1 - separator_length ||
        directory_length + separator_length > (size_t)-1 - name_length ||
        directory_length + separator_length + name_length > (size_t)-1 - 1) {
        return NULL;
    }

    total_length = directory_length + separator_length + name_length + 1;
    result = (char *)malloc(total_length);
    if (result == NULL) {
        return NULL;
    }

    memcpy(result, directory, directory_length);
    if (separator_length != 0) {
        result[directory_length] = '\\';
    }
    memcpy(result + directory_length + separator_length, name, name_length + 1);
    return result;
}

static int ltf_has_matching_suffix(const char *name,
                                   const char *const *exts,
                                   size_t ext_count)
{
    size_t name_length = strlen(name);
    size_t i;

    for (i = 0; i < ext_count; ++i) {
        const char *ext = exts[i];
        size_t ext_length;
        size_t j;
        int matches = 1;

        if (ext == NULL) {
            continue;
        }

        ext_length = strlen(ext);
        if (ext_length > name_length) {
            continue;
        }

        for (j = 0; j < ext_length; ++j) {
            unsigned char a = (unsigned char)name[name_length - ext_length + j];
            unsigned char b = (unsigned char)ext[j];

            if (a >= 'A' && a <= 'Z') {
                a = (unsigned char)(a - 'A' + 'a');
            }
            if (b >= 'A' && b <= 'Z') {
                b = (unsigned char)(b - 'A' + 'a');
            }
            if (a != b) {
                matches = 0;
                break;
            }
        }

        if (matches) {
            return 1;
        }
    }

    return 0;
}

static int ltf_add_path(LTF_CONTEXT *context, char *path)
{
    if (context->count == (size_t)-1) {
        free(path);
        context->allocation_failed = 1;
        return 0;
    }

    if (context->count == context->capacity) {
        size_t new_capacity = context->capacity == 0 ? 16 : context->capacity * 2;
        char **new_paths;

        if (new_capacity < context->capacity ||
            new_capacity == (size_t)-1 ||
            new_capacity + 1 > (size_t)-1 / sizeof(*new_paths)) {
            free(path);
            context->allocation_failed = 1;
            return 0;
        }

        new_paths = (char **)malloc((new_capacity + 1) * sizeof(*new_paths));
        if (new_paths == NULL) {
            free(path);
            context->allocation_failed = 1;
            return 0;
        }

        if (context->count != 0) {
            memcpy(new_paths, context->paths,
                   context->count * sizeof(*new_paths));
        }
        free(context->paths);
        context->paths = new_paths;
        context->capacity = new_capacity;
    }

    context->paths[context->count++] = path;
    context->paths[context->count] = NULL;
    return 1;
}

static int ltf_walk_directory(LTF_CONTEXT *context,
                              const char *directory,
                              const char *const *exts,
                              size_t ext_count)
{
    char *search_path;
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle;

    search_path = ltf_join_path(directory, "*");
    if (search_path == NULL) {
        context->allocation_failed = 1;
        return 0;
    }

    find_handle = FindFirstFileA(search_path, &find_data);
    free(search_path);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return 1;
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

            child_path = ltf_join_path(directory, name);
            if (child_path == NULL) {
                context->allocation_failed = 1;
                break;
            }

            if (!ltf_walk_directory(context, child_path, exts, ext_count)) {
                free(child_path);
                break;
            }
            free(child_path);
        } else if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) == 0 &&
                   ltf_has_matching_suffix(name, exts, ext_count)) {
            char *file_path = ltf_join_path(directory, name);

            if (file_path == NULL) {
                context->allocation_failed = 1;
                break;
            }
            if (!ltf_add_path(context, file_path)) {
                break;
            }
        }
    } while (FindNextFileA(find_handle, &find_data));

    FindClose(find_handle);
    return !context->allocation_failed;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    LTF_CONTEXT context;
    size_t i;

    if (out_paths == NULL) {
        return 0;
    }
    *out_paths = NULL;

    if (dirs == NULL || exts == NULL || dir_count == 0 || ext_count == 0) {
        return 0;
    }

    context.paths = NULL;
    context.count = 0;
    context.capacity = 0;
    context.allocation_failed = 0;

    for (i = 0; i < dir_count; ++i) {
        if (dirs[i] != NULL &&
            !ltf_walk_directory(&context, dirs[i], exts, ext_count)) {
            break;
        }
    }

    if (context.allocation_failed) {
        for (i = 0; i < context.count; ++i) {
            free(context.paths[i]);
        }
        free(context.paths);
        return 0;
    }

    if (context.count == 0) {
        free(context.paths);
        return 0;
    }

    *out_paths = context.paths;
    return context.count;
}