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
    const char *const *exts;
    size_t ext_count;
    int failed;
} list_target_files_context;

static char *list_target_files_join(const char *directory, const char *name)
{
    size_t directory_length = strlen(directory);
    size_t name_length = strlen(name);
    int needs_separator = directory_length != 0 &&
        directory[directory_length - 1] != '\\' &&
        directory[directory_length - 1] != '/';
    size_t total_length;

    if (directory_length > (size_t)-1 - name_length - (size_t)needs_separator - 1)
        return NULL;

    total_length = directory_length + name_length + (size_t)needs_separator + 1;
    char *result = (char *)malloc(total_length);
    if (result == NULL)
        return NULL;

    memcpy(result, directory, directory_length);
    if (needs_separator)
        result[directory_length++] = '\\';
    memcpy(result + directory_length, name, name_length + 1);
    return result;
}

static int list_target_files_suffix_matches(const char *name, const char *suffix)
{
    size_t name_length;
    size_t suffix_length;
    size_t i;

    if (name == NULL || suffix == NULL)
        return 0;

    name_length = strlen(name);
    suffix_length = strlen(suffix);
    if (suffix_length > name_length)
        return 0;

    for (i = 0; i < suffix_length; ++i) {
        unsigned char a = (unsigned char)name[name_length - suffix_length + i];
        unsigned char b = (unsigned char)suffix[i];

        if (a >= 'A' && a <= 'Z')
            a = (unsigned char)(a - 'A' + 'a');
        if (b >= 'A' && b <= 'Z')
            b = (unsigned char)(b - 'A' + 'a');
        if (a != b)
            return 0;
    }

    return 1;
}

static int list_target_files_matches_any(const list_target_files_context *context,
                                         const char *name)
{
    size_t i;

    for (i = 0; i < context->ext_count; ++i) {
        if (list_target_files_suffix_matches(name, context->exts[i]))
            return 1;
    }
    return 0;
}

static int list_target_files_append(list_target_files_context *context,
                                    const char *path)
{
    size_t length = strlen(path);
    char *copy;

    if (context->count > (size_t)-1 / sizeof(*context->paths) - 2)
        return 0;

    if (context->count + 1 >= context->capacity) {
        size_t new_capacity = context->capacity == 0 ? 16 : context->capacity;
        char **new_paths;

        while (new_capacity <= context->count + 1) {
            if (new_capacity > (size_t)-1 / 2) {
                new_capacity = context->count + 2;
                break;
            }
            new_capacity *= 2;
        }

        if (new_capacity > (size_t)-1 / sizeof(*context->paths))
            return 0;

        new_paths = (char **)realloc(context->paths,
                                     new_capacity * sizeof(*context->paths));
        if (new_paths == NULL)
            return 0;

        context->paths = new_paths;
        context->capacity = new_capacity;
    }

    if (length == (size_t)-1)
        return 0;
    copy = (char *)malloc(length + 1);
    if (copy == NULL)
        return 0;

    memcpy(copy, path, length + 1);
    context->paths[context->count++] = copy;
    context->paths[context->count] = NULL;
    return 1;
}

static void list_target_files_walk(list_target_files_context *context,
                                   const char *directory)
{
    char *search_path;
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle;

    if (context->failed)
        return;

    search_path = list_target_files_join(directory, "*");
    if (search_path == NULL) {
        context->failed = 1;
        return;
    }

    find_handle = FindFirstFileA(search_path, &find_data);
    free(search_path);
    if (find_handle == INVALID_HANDLE_VALUE)
        return;

    do {
        char *entry_path;

        if (strcmp(find_data.cFileName, ".") == 0 ||
            strcmp(find_data.cFileName, "..") == 0)
            continue;

        entry_path = list_target_files_join(directory, find_data.cFileName);
        if (entry_path == NULL) {
            context->failed = 1;
            break;
        }

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT))
                list_target_files_walk(context, entry_path);
        } else if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) &&
                   list_target_files_matches_any(context, find_data.cFileName)) {
            if (!list_target_files_append(context, entry_path))
                context->failed = 1;
        }

        free(entry_path);
        if (context->failed)
            break;
    } while (FindNextFileA(find_handle, &find_data));

    FindClose(find_handle);
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    list_target_files_context context;
    size_t i;

    if (out_paths == NULL)
        return 0;

    *out_paths = NULL;

    if (dirs == NULL || exts == NULL || dir_count == 0 || ext_count == 0)
        return 0;

    memset(&context, 0, sizeof(context));
    context.exts = exts;
    context.ext_count = ext_count;

    for (i = 0; i < dir_count && !context.failed; ++i) {
        if (dirs[i] != NULL)
            list_target_files_walk(&context, dirs[i]);
    }

    if (context.failed) {
        for (i = 0; i < context.count; ++i)
            free(context.paths[i]);
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