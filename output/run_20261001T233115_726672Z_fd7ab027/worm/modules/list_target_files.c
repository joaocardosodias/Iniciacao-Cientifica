#include <windows.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

typedef struct list_target_files_context {
    const char *const *exts;
    size_t ext_count;
    char **paths;
    size_t count;
    size_t capacity;
    int failed;
} list_target_files_context;

static char *list_target_files_join(const char *base, const char *name)
{
    size_t base_len = strlen(base);
    size_t name_len = strlen(name);
    int needs_separator = base_len != 0 &&
        base[base_len - 1] != '\\' && base[base_len - 1] != '/';
    size_t separator_len = needs_separator ? 1u : 0u;
    size_t max_size = (size_t)-1;
    char *result;

    if (base_len > max_size - separator_len ||
        base_len + separator_len > max_size - name_len ||
        base_len + separator_len + name_len == max_size) {
        return NULL;
    }

    result = (char *)malloc(base_len + separator_len + name_len + 1);
    if (result == NULL) {
        return NULL;
    }

    memcpy(result, base, base_len);
    if (needs_separator) {
        result[base_len] = '\\';
    }
    memcpy(result + base_len + separator_len, name, name_len + 1);
    return result;
}

static int list_target_files_matches(const char *name,
                                     const list_target_files_context *context)
{
    size_t name_len = strlen(name);
    size_t i;

    for (i = 0; i < context->ext_count; ++i) {
        const char *ext = context->exts[i];
        size_t ext_len;

        if (ext == NULL) {
            continue;
        }

        ext_len = strlen(ext);
        if (name_len >= ext_len &&
            _stricmp(name + name_len - ext_len, ext) == 0) {
            return 1;
        }
    }

    return 0;
}

static int list_target_files_append(list_target_files_context *context,
                                    char *path)
{
    size_t max_slots = (size_t)-1 / sizeof(*context->paths);
    size_t new_capacity;
    char **new_paths;

    if (context->count >= max_slots - 1) {
        return 0;
    }

    if (context->count == context->capacity) {
        if (context->capacity == 0) {
            new_capacity = 16;
        } else if (context->capacity > (max_slots - 1) / 2) {
            new_capacity = max_slots - 1;
        } else {
            new_capacity = context->capacity * 2;
        }

        if (new_capacity <= context->count || new_capacity > max_slots - 1) {
            return 0;
        }

        new_paths = (char **)malloc((new_capacity + 1) * sizeof(*new_paths));
        if (new_paths == NULL) {
            return 0;
        }

        if (context->paths != NULL) {
            memcpy(new_paths, context->paths,
                   (context->count + 1) * sizeof(*new_paths));
            free(context->paths);
        }

        context->paths = new_paths;
        context->capacity = new_capacity;
    }

    context->paths[context->count++] = path;
    context->paths[context->count] = NULL;
    return 1;
}

static void list_target_files_walk(const char *directory,
                                   list_target_files_context *context)
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
        char *child_path;

        if (strcmp(find_data.cFileName, ".") == 0 ||
            strcmp(find_data.cFileName, "..") == 0) {
            continue;
        }

        child_path = list_target_files_join(directory, find_data.cFileName);
        if (child_path == NULL) {
            context->failed = 1;
            break;
        }

        if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY) != 0) {
            if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_REPARSE_POINT) == 0) {
                list_target_files_walk(child_path, context);
            }
            free(child_path);
            if (context->failed) {
                break;
            }
        } else if ((find_data.dwFileAttributes & FILE_ATTRIBUTE_DEVICE) == 0 &&
                   list_target_files_matches(find_data.cFileName, context)) {
            if (!list_target_files_append(context, child_path)) {
                free(child_path);
                context->failed = 1;
                break;
            }
        } else {
            free(child_path);
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
    list_target_files_context context;
    size_t i;

    if (out_paths == NULL) {
        return 0;
    }
    *out_paths = NULL;

    if ((dir_count != 0 && dirs == NULL) ||
        (ext_count != 0 && exts == NULL) ||
        ext_count == 0) {
        return 0;
    }

    memset(&context, 0, sizeof(context));
    context.exts = exts;
    context.ext_count = ext_count;

    for (i = 0; i < dir_count && !context.failed; ++i) {
        if (dirs[i] != NULL) {
            list_target_files_walk(dirs[i], &context);
        }
    }

    if (context.failed) {
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