#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char **paths;
    size_t count;
    size_t capacity;
    const char *const *exts;
    size_t ext_count;
    int failed;
} ltf_context;

static int ltf_is_separator(char c)
{
    return c == '\\' || c == '/';
}

static char ltf_ascii_lower(char c)
{
    if (c >= 'A' && c <= 'Z')
        return (char)(c + ('a' - 'A'));
    return c;
}

static int ltf_name_matches(const char *name, const char *const *exts, size_t ext_count)
{
    size_t name_len = strlen(name);
    size_t i;

    for (i = 0; i < ext_count; ++i) {
        const char *ext = exts[i];
        size_t ext_len;
        size_t j;

        if (ext == NULL || ext[0] == '\0')
            continue;

        ext_len = strlen(ext);
        if (name_len < ext_len)
            continue;

        for (j = 0; j < ext_len; ++j) {
            if (ltf_ascii_lower(name[name_len - ext_len + j]) !=
                ltf_ascii_lower(ext[j]))
                break;
        }
        if (j == ext_len)
            return 1;
    }

    return 0;
}

static char *ltf_join_path(const char *base, const char *name)
{
    size_t base_len = strlen(base);
    size_t name_len = strlen(name);
    int add_separator = base_len != 0 && !ltf_is_separator(base[base_len - 1]);
    size_t total;
    char *joined;

    if (base_len > SIZE_MAX - name_len)
        return NULL;
    total = base_len + name_len;
    if (add_separator) {
        if (total == SIZE_MAX)
            return NULL;
        ++total;
    }
    if (total == SIZE_MAX)
        return NULL;
    ++total;

    joined = (char *)malloc(total);
    if (joined == NULL)
        return NULL;

    if (base_len != 0)
        memcpy(joined, base, base_len);
    if (add_separator)
        joined[base_len++] = '\\';
    memcpy(joined + base_len, name, name_len + 1);
    return joined;
}

static int ltf_add_path(ltf_context *context, char *path)
{
    char **new_paths;
    size_t needed;
    size_t new_capacity;

    if (context->count > SIZE_MAX - 2) {
        free(path);
        return 0;
    }
    needed = context->count + 2;

    if (needed > context->capacity) {
        new_capacity = context->capacity == 0 ? 16 : context->capacity;
        while (new_capacity < needed) {
            if (new_capacity > SIZE_MAX / 2) {
                new_capacity = needed;
                break;
            }
            new_capacity *= 2;
        }
        if (new_capacity > SIZE_MAX / sizeof(*context->paths)) {
            free(path);
            return 0;
        }
        new_paths = (char **)realloc(context->paths,
                                     new_capacity * sizeof(*context->paths));
        if (new_paths == NULL) {
            free(path);
            return 0;
        }
        context->paths = new_paths;
        context->capacity = new_capacity;
    }

    context->paths[context->count++] = path;
    context->paths[context->count] = NULL;
    return 1;
}

static void ltf_walk_directory(ltf_context *context, const char *directory)
{
    char *search_pattern;
    WIN32_FIND_DATAA find_data;
    HANDLE find_handle;

    if (context->failed)
        return;

    search_pattern = ltf_join_path(directory, "*");
    if (search_pattern == NULL) {
        context->failed = 1;
        return;
    }

    find_handle = FindFirstFileA(search_pattern, &find_data);
    free(search_pattern);
    if (find_handle == INVALID_HANDLE_VALUE)
        return;

    do {
        const char *name = find_data.cFileName;

        if (strcmp(name, ".") == 0 || strcmp(name, "..") == 0)
            continue;

        if (find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) {
            char *child_directory;

            if (find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT)
                continue;

            child_directory = ltf_join_path(directory, name);
            if (child_directory == NULL) {
                context->failed = 1;
                break;
            }
            ltf_walk_directory(context, child_directory);
            free(child_directory);
            if (context->failed)
                break;
        } else if (!(find_data.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) &&
                   ltf_name_matches(name, context->exts, context->ext_count)) {
            char *file_path = ltf_join_path(directory, name);

            if (file_path == NULL || !ltf_add_path(context, file_path)) {
                context->failed = 1;
                break;
            }
        }
    } while (FindNextFileA(find_handle, &find_data));

    FindClose(find_handle);
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    ltf_context context;
    size_t i;

    if (out_paths == NULL)
        return 0;

    *out_paths = NULL;
    if (dirs == NULL || exts == NULL)
        return 0;

    memset(&context, 0, sizeof(context));
    context.exts = exts;
    context.ext_count = ext_count;

    for (i = 0; i < dir_count; ++i) {
        if (dirs[i] != NULL)
            ltf_walk_directory(&context, dirs[i]);
        if (context.failed)
            break;
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