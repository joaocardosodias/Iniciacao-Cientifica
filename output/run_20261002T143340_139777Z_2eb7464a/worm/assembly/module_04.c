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

typedef struct {
    char **paths;
    size_t count;
    size_t capacity;
    int failed;
} ListTargetFilesContext;

static char *list_target_files_join(const char *base, const char *component)
{
    size_t base_len = strlen(base);
    size_t component_len = strlen(component);
    int needs_separator = base_len != 0 &&
        base[base_len - 1] != '\\' && base[base_len - 1] != '/';
    size_t separator_len = needs_separator ? 1u : 0u;
    size_t total;

    if (base_len > (size_t)-1 - separator_len ||
        base_len + separator_len > (size_t)-1 - component_len ||
        base_len + separator_len + component_len > (size_t)-1 - 1u) {
        return NULL;
    }

    total = base_len + separator_len + component_len + 1u;
    char *result = (char *)malloc(total);
    if (result == NULL) {
        return NULL;
    }

    memcpy(result, base, base_len);
    if (needs_separator) {
        result[base_len++] = '\\';
    }
    memcpy(result + base_len, component, component_len + 1u);
    return result;
}

static int list_target_files_matches_extension(
    const char *name,
    const char *const *exts,
    size_t ext_count)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < ext_count; ++i) {
        if (exts[i] == NULL) {
            continue;
        }

        size_t ext_len = strlen(exts[i]);
        if (ext_len != 0 && name_len >= ext_len &&
            _stricmp(name + name_len - ext_len, exts[i]) == 0) {
            return 1;
        }
    }

    return 0;
}

static int list_target_files_add(
    ListTargetFilesContext *context,
    char *path)
{
    if (context->count == context->capacity) {
        size_t new_capacity = context->capacity == 0 ? 16u : context->capacity * 2u;
        if (new_capacity < context->capacity ||
            new_capacity > (size_t)-1 / sizeof(*context->paths)) {
            free(path);
            context->failed = 1;
            return 0;
        }

        char **new_paths = (char **)realloc(
            context->paths, new_capacity * sizeof(*context->paths));
        if (new_paths == NULL) {
            free(path);
            context->failed = 1;
            return 0;
        }

        context->paths = new_paths;
        context->capacity = new_capacity;
    }

    context->paths[context->count++] = path;
    return 1;
}

static void list_target_files_walk(
    const char *directory,
    const char *const *exts,
    size_t ext_count,
    ListTargetFilesContext *context)
{
    char *search_pattern;
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle;

    if (context->failed) {
        return;
    }

    search_pattern = list_target_files_join(directory, "*");
    if (search_pattern == NULL) {
        context->failed = 1;
        return;
    }

    find_handle = FindFirstFileA(search_pattern, &find_data);
    free(search_pattern);
    if (find_handle == INVALID_HANDLE_VALUE) {
        return;
    }

    do {
        char *entry_path;

        if ((find_data.cFileName[0] == '.' &&
             find_data.cFileName[1] == '\0') ||
            (find_data.cFileName[0] == '.' &&
             find_data.cFileName[1] == '.' &&
             find_data.cFileName[2] == '\0')) {
            continue;
        }

        if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) != 0) {
                continue;
            }

            entry_path = list_target_files_join(directory, find_data.cFileName);
            if (entry_path == NULL) {
                context->failed = 1;
                break;
            }

            list_target_files_walk(entry_path, exts, ext_count, context);
            free(entry_path);
            if (context->failed) {
                break;
            }
        } else if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) == 0 &&
                   list_target_files_matches_extension(
                       find_data.cFileName, exts, ext_count)) {
            entry_path = list_target_files_join(directory, find_data.cFileName);
            if (entry_path == NULL) {
                context->failed = 1;
                break;
            }

            if (!list_target_files_add(context, entry_path)) {
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
    ListTargetFilesContext context = { 0 };
    char **result;

    if (out_paths == NULL) {
        return 0;
    }
    *out_paths = NULL;

    if ((dir_count != 0 && dirs == NULL) ||
        (ext_count != 0 && exts == NULL)) {
        return 0;
    }

    for (size_t i = 0; i < dir_count && !context.failed; ++i) {
        if (dirs[i] != NULL) {
            list_target_files_walk(dirs[i], exts, ext_count, &context);
        }
    }

    if (context.failed || context.count == 0 ||
        context.count >= (size_t)-1 / sizeof(*result)) {
        for (size_t i = 0; i < context.count; ++i) {
            free(context.paths[i]);
        }
        free(context.paths);
        return 0;
    }

    result = (char **)calloc(context.count + 1u, sizeof(*result));
    if (result == NULL) {
        for (size_t i = 0; i < context.count; ++i) {
            free(context.paths[i]);
        }
        free(context.paths);
        return 0;
    }

    for (size_t i = 0; i < context.count; ++i) {
        result[i] = context.paths[i];
    }

    free(context.paths);
    *out_paths = result;
    return context.count;
}