#define _GNU_SOURCE
#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

static void free_path_array(char **paths, size_t count)
{
    size_t i;

    for (i = 0; i < count; ++i)
        free(paths[i]);
    free(paths);
}

static int push_path(char ***array, size_t *count, size_t *capacity, char *path)
{
    size_t max_capacity = SIZE_MAX / sizeof(**array);

    if (*count >= max_capacity - 1)
        return -1;

    if (*count + 1 >= *capacity) {
        size_t new_capacity = *capacity ? *capacity : 16;
        char **new_array;

        while (new_capacity <= *count + 1) {
            if (new_capacity > max_capacity / 2) {
                new_capacity = max_capacity;
                break;
            }
            new_capacity *= 2;
        }
        if (new_capacity <= *count + 1)
            return -1;

        new_array = realloc(*array, new_capacity * sizeof(**array));
        if (new_array == NULL)
            return -1;
        *array = new_array;
        *capacity = new_capacity;
    }

    (*array)[(*count)++] = path;
    return 0;
}

static char *expand_directory(const char *path)
{
    const char *prefix = "";
    size_t prefix_len = 0;
    size_t suffix_len;
    char *expanded;

    if (path[0] == '~') {
        prefix = getenv("HOME");
        if (prefix == NULL)
            return NULL;
        prefix_len = strlen(prefix);
        ++path;
    }

    suffix_len = strlen(path);
    if (prefix_len > SIZE_MAX - suffix_len - 1)
        return NULL;

    expanded = malloc(prefix_len + suffix_len + 1);
    if (expanded == NULL)
        return NULL;

    memcpy(expanded, prefix, prefix_len);
    memcpy(expanded + prefix_len, path, suffix_len + 1);
    return expanded;
}

static char *join_path(const char *directory, const char *name)
{
    size_t directory_len = strlen(directory);
    size_t name_len = strlen(name);
    size_t separator = directory_len != 0 && directory[directory_len - 1] != '/';
    char *joined;

    if (directory_len > SIZE_MAX - name_len ||
        directory_len + name_len > SIZE_MAX - separator - 1)
        return NULL;

    joined = malloc(directory_len + separator + name_len + 1);
    if (joined == NULL)
        return NULL;

    memcpy(joined, directory, directory_len);
    if (separator)
        joined[directory_len] = '/';
    memcpy(joined + directory_len + separator, name, name_len + 1);
    return joined;
}

static int matches_extension(const char *name, const char *const *exts,
                             size_t ext_count)
{
    size_t name_len = strlen(name);
    size_t i;

    if (exts == NULL)
        return 0;

    for (i = 0; i < ext_count; ++i) {
        size_t ext_len;

        if (exts[i] == NULL)
            continue;
        ext_len = strlen(exts[i]);
        if (ext_len <= name_len &&
            memcmp(name + name_len - ext_len, exts[i], ext_len) == 0)
            return 1;
    }
    return 0;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    char **stack = NULL;
    char **paths = NULL;
    size_t stack_count = 0, stack_capacity = 0;
    size_t path_count = 0, path_capacity = 0;
    char *current = NULL;
    DIR *dir = NULL;
    size_t i;

    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    if (dirs == NULL || exts == NULL || ext_count == 0)
        return 0;

    for (i = 0; i < dir_count; ++i) {
        char *root;

        if (dirs[i] == NULL)
            continue;
        if (dirs[i][0] == '~' && getenv("HOME") == NULL)
            continue;

        root = expand_directory(dirs[i]);
        if (root == NULL)
            goto fail;
        if (push_path(&stack, &stack_count, &stack_capacity, root) != 0) {
            free(root);
            goto fail;
        }
    }

    while (stack_count != 0) {
        struct dirent *entry;

        current = stack[--stack_count];
        dir = opendir(current);
        if (dir == NULL) {
            free(current);
            current = NULL;
            continue;
        }

        while ((entry = readdir(dir)) != NULL) {
            char *child;
            struct stat st;

            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0)
                continue;

            child = join_path(current, entry->d_name);
            if (child == NULL)
                goto fail;

            if (lstat(child, &st) != 0) {
                free(child);
                continue;
            }

            if (S_ISDIR(st.st_mode)) {
                if (push_path(&stack, &stack_count, &stack_capacity,
                              child) != 0) {
                    free(child);
                    goto fail;
                }
            } else if (S_ISREG(st.st_mode) &&
                       matches_extension(entry->d_name, exts, ext_count)) {
                if (push_path(&paths, &path_count, &path_capacity,
                              child) != 0) {
                    free(child);
                    goto fail;
                }
            } else {
                free(child);
            }
        }

        closedir(dir);
        dir = NULL;
        free(current);
        current = NULL;
    }

    free(stack);
    if (path_count != 0) {
        paths[path_count] = NULL;
        *out_paths = paths;
    } else {
        free(paths);
    }
    return path_count;

fail:
    if (dir != NULL)
        closedir(dir);
    free(current);
    free_path_array(stack, stack_count);
    free_path_array(paths, path_count);
    return 0;
}