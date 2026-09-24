#define _GNU_SOURCE
#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct list_target_files_context {
    const char *const *exts;
    size_t ext_count;
    char **paths;
    size_t count;
    size_t capacity;
};

static char *list_target_files_join(const char *directory, const char *name)
{
    size_t directory_length = strlen(directory);
    size_t name_length = strlen(name);
    int needs_separator = directory_length != 0 &&
        directory[directory_length - 1] != '/';

    if (directory_length > SIZE_MAX - name_length - (size_t)needs_separator - 1)
        return NULL;

    size_t length = directory_length + name_length +
        (size_t)needs_separator + 1;
    char *path = malloc(length);
    if (path == NULL)
        return NULL;

    memcpy(path, directory, directory_length);
    size_t offset = directory_length;
    if (needs_separator)
        path[offset++] = '/';
    memcpy(path + offset, name, name_length + 1);
    return path;
}

static int list_target_files_matches(const char *name,
                                     const char *const *exts,
                                     size_t ext_count)
{
    size_t name_length = strlen(name);

    for (size_t i = 0; i < ext_count; ++i) {
        if (exts == NULL || exts[i] == NULL)
            continue;

        size_t extension_length = strlen(exts[i]);
        if (name_length >= extension_length &&
            memcmp(name + name_length - extension_length,
                   exts[i], extension_length) == 0)
            return 1;
    }

    return 0;
}

static int list_target_files_append(struct list_target_files_context *context,
                                    char *path)
{
    if (context->count == SIZE_MAX)
        return -1;

    if (context->count + 1 >= context->capacity) {
        size_t new_capacity = context->capacity == 0 ? 16 : context->capacity;
        while (new_capacity <= context->count + 1) {
            if (new_capacity > SIZE_MAX / 2) {
                new_capacity = context->count + 2;
                break;
            }
            new_capacity *= 2;
        }
        if (new_capacity > SIZE_MAX / sizeof(*context->paths))
            return -1;

        char **new_paths = realloc(context->paths,
                                   new_capacity * sizeof(*context->paths));
        if (new_paths == NULL)
            return -1;

        context->paths = new_paths;
        context->capacity = new_capacity;
    }

    context->paths[context->count++] = path;
    context->paths[context->count] = NULL;
    return 0;
}

static int list_target_files_walk(const char *directory,
                                  struct list_target_files_context *context)
{
    DIR *stream = opendir(directory);
    if (stream == NULL)
        return 0;

    struct dirent *entry;
    while ((entry = readdir(stream)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        char *path = list_target_files_join(directory, entry->d_name);
        if (path == NULL) {
            closedir(stream);
            return -1;
        }

        struct stat status;
        if (lstat(path, &status) != 0) {
            free(path);
            continue;
        }

        if (S_ISDIR(status.st_mode)) {
            int result = list_target_files_walk(path, context);
            free(path);
            if (result != 0) {
                closedir(stream);
                return -1;
            }
        } else if (S_ISREG(status.st_mode) &&
                   list_target_files_matches(entry->d_name, context->exts,
                                             context->ext_count)) {
            if (list_target_files_append(context, path) != 0) {
                free(path);
                closedir(stream);
                return -1;
            }
        } else {
            free(path);
        }
    }

    closedir(stream);
    return 0;
}

static char *list_target_files_expand(const char *directory)
{
    if (directory[0] != '~')
        return strdup(directory);

    const char *home = getenv("HOME");
    if (home == NULL)
        return NULL;

    size_t home_length = strlen(home);
    size_t suffix_length = strlen(directory + 1);
    if (home_length > SIZE_MAX - suffix_length - 1)
        return NULL;

    char *expanded = malloc(home_length + suffix_length + 1);
    if (expanded == NULL)
        return NULL;

    memcpy(expanded, home, home_length);
    memcpy(expanded + home_length, directory + 1, suffix_length + 1);
    return expanded;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (out_paths == NULL)
        return 0;

    *out_paths = NULL;

    struct list_target_files_context context = {
        .exts = exts,
        .ext_count = ext_count,
        .paths = NULL,
        .count = 0,
        .capacity = 0
    };

    if (dirs != NULL) {
        for (size_t i = 0; i < dir_count; ++i) {
            if (dirs[i] == NULL)
                continue;

            char *directory = list_target_files_expand(dirs[i]);
            if (directory == NULL) {
                if (dirs[i][0] == '~' && getenv("HOME") == NULL)
                    continue;
                for (size_t j = 0; j < context.count; ++j)
                    free(context.paths[j]);
                free(context.paths);
                return 0;
            }

            int result = list_target_files_walk(directory, &context);
            free(directory);
            if (result != 0) {
                for (size_t j = 0; j < context.count; ++j)
                    free(context.paths[j]);
                free(context.paths);
                return 0;
            }
        }
    }

    if (context.count == 0) {
        free(context.paths);
        return 0;
    }

    *out_paths = context.paths;
    return context.count;
}