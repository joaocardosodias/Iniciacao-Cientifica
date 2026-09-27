#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct target_file_list {
    char **paths;
    size_t count;
    size_t capacity;
    const char *const *exts;
    size_t ext_count;
    int failed;
};

static char *target_join_path(const char *dir, const char *name)
{
    size_t dir_len = strlen(dir);
    size_t name_len = strlen(name);
    int has_slash = dir_len != 0 && dir[dir_len - 1] == '/';
    char *joined = malloc(dir_len + name_len + (has_slash ? 1 : 2));

    if (joined == NULL)
        return NULL;

    memcpy(joined, dir, dir_len);
    if (!has_slash)
        joined[dir_len++] = '/';
    memcpy(joined + dir_len, name, name_len + 1);
    return joined;
}

static int target_matches_extension(const char *name,
                                    const struct target_file_list *list)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < list->ext_count; ++i) {
        const char *ext = list->exts[i];
        size_t ext_len;

        if (ext == NULL)
            continue;
        ext_len = strlen(ext);
        if (name_len >= ext_len &&
            memcmp(name + name_len - ext_len, ext, ext_len) == 0)
            return 1;
    }
    return 0;
}

static void target_add_path(struct target_file_list *list, const char *path)
{
    char *copy;

    if (list->failed)
        return;

    if (list->count + 1 >= list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 16 : list->capacity * 2;
        char **new_paths = realloc(list->paths,
                                   new_capacity * sizeof(*new_paths));
        if (new_paths == NULL) {
            list->failed = 1;
            return;
        }
        list->paths = new_paths;
        list->capacity = new_capacity;
    }

    copy = strdup(path);
    if (copy == NULL) {
        list->failed = 1;
        return;
    }

    list->paths[list->count++] = copy;
    list->paths[list->count] = NULL;
}

static void target_walk_directory(struct target_file_list *list,
                                  const char *path)
{
    DIR *dir;
    struct dirent *entry;

    if (list->failed)
        return;

    dir = opendir(path);
    if (dir == NULL)
        return;

    while (!list->failed && (entry = readdir(dir)) != NULL) {
        char *child;
        struct stat st;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        child = target_join_path(path, entry->d_name);
        if (child == NULL) {
            list->failed = 1;
            break;
        }

        if (lstat(child, &st) == 0) {
            if (S_ISDIR(st.st_mode)) {
                target_walk_directory(list, child);
            } else if (S_ISREG(st.st_mode)) {
                if (target_matches_extension(entry->d_name, list))
                    target_add_path(list, child);
            } else if (S_ISLNK(st.st_mode) &&
                       stat(child, &st) == 0 &&
                       S_ISREG(st.st_mode) &&
                       target_matches_extension(entry->d_name, list)) {
                target_add_path(list, child);
            }
        }
        free(child);
    }

    closedir(dir);
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    struct target_file_list list = {0};

    if (out_paths == NULL)
        return 0;
    *out_paths = NULL;

    if (dirs == NULL || exts == NULL || ext_count == 0)
        return 0;

    list.exts = exts;
    list.ext_count = ext_count;

    for (size_t i = 0; i < dir_count && !list.failed; ++i) {
        const char *dir = dirs[i];
        char *expanded = NULL;
        struct stat st;

        if (dir == NULL)
            continue;

        if (dir[0] == '~') {
            const char *home = getenv("HOME");
            if (home != NULL) {
                size_t home_len = strlen(home);
                size_t suffix_len = strlen(dir + 1);
                expanded = malloc(home_len + suffix_len + 1);
                if (expanded == NULL) {
                    list.failed = 1;
                    break;
                }
                memcpy(expanded, home, home_len);
                memcpy(expanded + home_len, dir + 1, suffix_len + 1);
                dir = expanded;
            }
        }

        if (stat(dir, &st) == 0 && S_ISDIR(st.st_mode))
            target_walk_directory(&list, dir);

        free(expanded);
    }

    if (list.failed) {
        for (size_t i = 0; i < list.count; ++i)
            free(list.paths[i]);
        free(list.paths);
        return 0;
    }

    if (list.count == 0) {
        free(list.paths);
        return 0;
    }

    *out_paths = list.paths;
    return list.count;
}