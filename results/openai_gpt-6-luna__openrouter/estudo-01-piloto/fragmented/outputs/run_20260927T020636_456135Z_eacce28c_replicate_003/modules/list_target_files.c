#define _GNU_SOURCE
#include <dirent.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct target_file_list {
    char **paths;
    size_t count;
    size_t capacity;
};

static void free_target_file_list(struct target_file_list *list)
{
    size_t i;

    for (i = 0; i < list->count; ++i)
        free(list->paths[i]);
    free(list->paths);
    list->paths = NULL;
    list->count = 0;
    list->capacity = 0;
}

static char *join_target_path(const char *parent, const char *name)
{
    size_t parent_len = strlen(parent);
    size_t name_len = strlen(name);
    int need_slash = parent_len != 0 && parent[parent_len - 1] != '/';
    size_t total;
    char *path;

    if (name_len == SIZE_MAX ||
        parent_len > SIZE_MAX - name_len - 1 - (size_t)need_slash)
        return NULL;

    total = parent_len + name_len + (size_t)need_slash + 1;
    path = malloc(total);
    if (path == NULL)
        return NULL;

    memcpy(path, parent, parent_len);
    if (need_slash)
        path[parent_len++] = '/';
    memcpy(path + parent_len, name, name_len + 1);
    return path;
}

static int target_file_matches(const char *name,
                               const char *const *exts,
                               size_t ext_count)
{
    size_t name_len = strlen(name);
    size_t i;

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

static int add_target_file(struct target_file_list *list, char *path)
{
    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 16 : list->capacity * 2;
        char **new_paths;

        if (list->capacity != 0 && new_capacity < list->capacity)
            return -1;
        if (new_capacity > SIZE_MAX / sizeof(*new_paths) - 1)
            return -1;
        new_paths = realloc(list->paths,
                            (new_capacity + 1) * sizeof(*new_paths));
        if (new_paths == NULL)
            return -1;
        list->paths = new_paths;
        list->capacity = new_capacity;
    }

    list->paths[list->count++] = path;
    list->paths[list->count] = NULL;
    return 0;
}

static int walk_target_directory(const char *path,
                                 const char *const *exts,
                                 size_t ext_count,
                                 struct target_file_list *list)
{
    DIR *dir = opendir(path);
    struct dirent *entry;

    if (dir == NULL)
        return 0;

    while ((entry = readdir(dir)) != NULL) {
        char *child;
        struct stat st;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        child = join_target_path(path, entry->d_name);
        if (child == NULL) {
            closedir(dir);
            return -1;
        }

        if (lstat(child, &st) == 0) {
            if (S_ISREG(st.st_mode) &&
                target_file_matches(entry->d_name, exts, ext_count)) {
                if (add_target_file(list, child) != 0) {
                    free(child);
                    closedir(dir);
                    return -1;
                }
                child = NULL;
            } else if (S_ISDIR(st.st_mode)) {
                if (walk_target_directory(child, exts, ext_count, list) != 0) {
                    free(child);
                    closedir(dir);
                    return -1;
                }
            }
        }
        free(child);
    }

    closedir(dir);
    return 0;
}

static char *expand_target_tilde(const char *path)
{
    const char *home;
    size_t home_len;
    size_t rest_len;
    char *expanded;

    if (path[0] != '~')
        return strdup(path);

    home = getenv("HOME");
    if (home == NULL)
        return strdup(path);

    home_len = strlen(home);
    rest_len = strlen(path + 1);
    if (rest_len == SIZE_MAX ||
        home_len > SIZE_MAX - rest_len - 1)
        return NULL;

    expanded = malloc(home_len + rest_len + 1);
    if (expanded == NULL)
        return NULL;

    memcpy(expanded, home, home_len);
    memcpy(expanded + home_len, path + 1, rest_len + 1);
    return expanded;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    struct target_file_list list = { NULL, 0, 0 };
    size_t i;

    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    for (i = 0; i < dir_count; ++i) {
        char *root;

        if (dirs == NULL || dirs[i] == NULL)
            continue;
        root = expand_target_tilde(dirs[i]);
        if (root == NULL) {
            free_target_file_list(&list);
            return 0;
        }
        if (walk_target_directory(root, exts, ext_count, &list) != 0) {
            free(root);
            free_target_file_list(&list);
            return 0;
        }
        free(root);
    }

    *out_paths = list.paths;
    return list.count;
}