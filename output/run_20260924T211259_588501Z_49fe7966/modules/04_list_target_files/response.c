#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

struct target_file_list {
    char **paths;
    size_t count;
    int failed;
};

static int target_file_matches(const char *name, const char *const *exts,
                               size_t ext_count)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < ext_count; ++i) {
        if (exts[i] == NULL)
            continue;

        size_t ext_len = strlen(exts[i]);
        if (ext_len <= name_len &&
            memcmp(name + name_len - ext_len, exts[i], ext_len) == 0)
            return 1;
    }

    return 0;
}

static char *target_file_join(const char *dir, const char *name)
{
    size_t dir_len = strlen(dir);
    int needs_slash = dir_len == 0 || dir[dir_len - 1] != '/';
    char *path = NULL;

    if (asprintf(&path, "%s%s%s", dir, needs_slash ? "/" : "", name) < 0)
        return NULL;

    return path;
}

static void target_file_add(struct target_file_list *list, const char *path)
{
    char *copy;
    char **new_paths;

    copy = strdup(path);
    if (copy == NULL) {
        list->failed = 1;
        return;
    }

    new_paths = reallocarray(list->paths, list->count + 2,
                             sizeof(*list->paths));
    if (new_paths == NULL) {
        free(copy);
        list->failed = 1;
        return;
    }

    list->paths = new_paths;
    list->paths[list->count++] = copy;
    list->paths[list->count] = NULL;
}

static void target_file_walk(const char *dir, const char *const *exts,
                             size_t ext_count, struct target_file_list *list)
{
    DIR *stream;
    struct dirent *entry;

    if (list->failed)
        return;

    stream = opendir(dir);
    if (stream == NULL)
        return;

    while (!list->failed && (entry = readdir(stream)) != NULL) {
        char *path;
        struct stat st;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        path = target_file_join(dir, entry->d_name);
        if (path == NULL) {
            list->failed = 1;
            break;
        }

        if (lstat(path, &st) != 0) {
            free(path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            target_file_walk(path, exts, ext_count, list);
        } else if (S_ISREG(st.st_mode) &&
                   target_file_matches(entry->d_name, exts, ext_count)) {
            target_file_add(list, path);
        }

        free(path);
    }

    closedir(stream);
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    struct target_file_list list = { NULL, 0, 0 };

    if (out_paths == NULL)
        return 0;

    *out_paths = NULL;

    if (dirs == NULL || exts == NULL || ext_count == 0)
        return 0;

    for (size_t i = 0; i < dir_count && !list.failed; ++i) {
        const char *dir;
        char *expanded = NULL;

        if (dirs[i] == NULL)
            continue;

        dir = dirs[i];
        if (dir[0] == '~') {
            const char *home = getenv("HOME");
            if (home != NULL) {
                if (asprintf(&expanded, "%s%s", home, dir + 1) < 0) {
                    list.failed = 1;
                    break;
                }
                dir = expanded;
            }
        }

        target_file_walk(dir, exts, ext_count, &list);
        free(expanded);
    }

    if (list.failed) {
        for (size_t i = 0; i < list.count; ++i)
            free(list.paths[i]);
        free(list.paths);
        return 0;
    }

    *out_paths = list.paths;
    return list.count;
}