#include <windows.h>
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

static char *list_target_files_join(const char *base, const char *name)
{
    size_t base_len = strlen(base);
    size_t name_len = strlen(name);
    int needs_separator = base_len != 0 &&
        base[base_len - 1] != '\\' && base[base_len - 1] != '/';

    if (base_len > (size_t)-1 - name_len - (size_t)needs_separator - 1)
        return NULL;

    size_t length = base_len + name_len + (size_t)needs_separator;
    char *result = (char *)malloc(length + 1);
    if (result == NULL)
        return NULL;

    memcpy(result, base, base_len);
    if (needs_separator)
        result[base_len++] = '\\';
    memcpy(result + base_len, name, name_len);
    result[length] = '\0';
    return result;
}

static int list_target_files_has_extension(
    const char *filename,
    const char *const *exts,
    size_t ext_count)
{
    size_t filename_len = strlen(filename);

    for (size_t i = 0; i < ext_count; ++i) {
        const char *ext = exts[i];
        if (ext == NULL)
            continue;

        size_t ext_len = strlen(ext);
        if (ext_len > filename_len)
            continue;

        const char *suffix = filename + filename_len - ext_len;
        size_t j = 0;
        while (j < ext_len) {
            unsigned char a = (unsigned char)suffix[j];
            unsigned char b = (unsigned char)ext[j];
            if (a >= 'A' && a <= 'Z')
                a = (unsigned char)(a - 'A' + 'a');
            if (b >= 'A' && b <= 'Z')
                b = (unsigned char)(b - 'A' + 'a');
            if (a != b)
                break;
            ++j;
        }
        if (j == ext_len)
            return 1;
    }

    return 0;
}

static int list_target_files_append(list_target_files_context *context,
                                   const char *path)
{
    if (context->count > (size_t)-1 - 2)
        return 0;

    char *copy = (char *)malloc(strlen(path) + 1);
    if (copy == NULL)
        return 0;
    strcpy(copy, path);

    if (context->count + 1 >= context->capacity) {
        size_t new_capacity = context->capacity == 0 ? 8 : context->capacity;
        while (new_capacity <= context->count + 1) {
            if (new_capacity > (size_t)-1 / 2) {
                free(copy);
                return 0;
            }
            new_capacity *= 2;
        }
        if (new_capacity > (size_t)-1 / sizeof(*context->paths)) {
            free(copy);
            return 0;
        }

        char **new_paths = (char **)realloc(
            context->paths, new_capacity * sizeof(*context->paths));
        if (new_paths == NULL) {
            free(copy);
            return 0;
        }
        context->paths = new_paths;
        context->capacity = new_capacity;
    }

    context->paths[context->count++] = copy;
    context->paths[context->count] = NULL;
    return 1;
}

static void list_target_files_walk(list_target_files_context *context,
                                   const char *directory)
{
    if (context->failed)
        return;

    char *search_path = list_target_files_join(directory, "*");
    if (search_path == NULL) {
        context->failed = 1;
        return;
    }

    WIN32_FIND_DATAA data;
    HANDLE find_handle = FindFirstFileA(search_path, &data);
    free(search_path);
    if (find_handle == INVALID_HANDLE_VALUE)
        return;

    do {
        if (strcmp(data.cFileName, ".") == 0 ||
            strcmp(data.cFileName, "..") == 0)
            continue;

        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if ((data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
                char *child_directory =
                    list_target_files_join(directory, data.cFileName);
                if (child_directory == NULL) {
                    context->failed = 1;
                    break;
                }
                list_target_files_walk(context, child_directory);
                free(child_directory);
                if (context->failed)
                    break;
            }
            continue;
        }

        if ((data.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) == 0 &&
            list_target_files_has_extension(data.cFileName, context->exts,
                                            context->ext_count)) {
            char *file_path =
                list_target_files_join(directory, data.cFileName);
            if (file_path == NULL) {
                context->failed = 1;
                break;
            }
            if (!list_target_files_append(context, file_path))
                context->failed = 1;
            free(file_path);
            if (context->failed)
                break;
        }
    } while (FindNextFileA(find_handle, &data));

    FindClose(find_handle);
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    if ((dir_count != 0 && dirs == NULL) ||
        (ext_count != 0 && exts == NULL) ||
        ext_count == 0)
        return 0;

    list_target_files_context context;
    context.paths = NULL;
    context.count = 0;
    context.capacity = 0;
    context.exts = exts;
    context.ext_count = ext_count;
    context.failed = 0;

    for (size_t i = 0; i < dir_count && !context.failed; ++i) {
        if (dirs[i] != NULL)
            list_target_files_walk(&context, dirs[i]);
    }

    if (context.failed) {
        for (size_t i = 0; i < context.count; ++i)
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