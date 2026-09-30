#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct target_file_list {
    char **paths;
    size_t count;
    size_t capacity;
};

static char *target_join_path(const char *base, const char *name)
{
    size_t base_len = strlen(base);
    size_t name_len = strlen(name);
    int add_slash = base_len != 0 && base[base_len - 1] != '/';

    if (base_len > SIZE_MAX - name_len - (size_t)add_slash - 1)
        return NULL;

    size_t total = base_len + name_len + (size_t)add_slash + 1;
    char *result = malloc(total);
    if (result == NULL)
        return NULL;

    memcpy(result, base, base_len);
    size_t offset = base_len;
    if (add_slash)
        result[offset++] = '/';
    memcpy(result + offset, name, name_len);
    result[offset + name_len] = '\0';
    return result;
}

static int target_has_suffix(const char *name, const char *const *exts,
                             size_t ext_count)
{
    size_t name_len = strlen(name);

    for (size_t i = 0; i < ext_count; i++) {
        if (exts[i] == NULL)
            continue;
        size_t ext_len = strlen(exts[i]);
        if (ext_len <= name_len &&
            memcmp(name + name_len - ext_len, exts[i], ext_len) == 0)
            return 1;
    }
    return 0;
}

static int target_append_path(struct target_file_list *list, const char *path)
{
    if (list->count == list->capacity) {
        size_t new_capacity = list->capacity == 0 ? 16 : list->capacity * 2;
        if (new_capacity < list->capacity ||
            new_capacity > SIZE_MAX / sizeof(*list->paths) - 1)
            return -1;

        char **new_paths = realloc(list->paths,
                                   (new_capacity + 1) * sizeof(*list->paths));
        if (new_paths == NULL)
            return -1;
        list->paths = new_paths;
        list->capacity = new_capacity;
    }

    char *copy = strdup(path);
    if (copy == NULL)
        return -1;

    list->paths[list->count++] = copy;
    list->paths[list->count] = NULL;
    return 0;
}

/* Takes ownership of fd. */
static int target_walk_directory(int fd, const char *path,
                                 const char *const *exts, size_t ext_count,
                                 struct target_file_list *list)
{
    DIR *dir = fdopendir(fd);
    if (dir == NULL) {
        close(fd);
        return 0;
    }

    int dir_fd = dirfd(dir);
    struct dirent *entry;
    int result = 0;

    for (;;) {
        errno = 0;
        entry = readdir(dir);
        if (entry == NULL)
            break;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        struct stat st;
        if (fstatat(dir_fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
            continue;

        if (S_ISREG(st.st_mode)) {
            if (target_has_suffix(entry->d_name, exts, ext_count)) {
                char *file_path = target_join_path(path, entry->d_name);
                if (file_path == NULL ||
                    target_append_path(list, file_path) < 0) {
                    free(file_path);
                    result = -1;
                    break;
                }
                free(file_path);
            }
            continue;
        }

        if (!S_ISDIR(st.st_mode))
            continue;

        int child_fd = openat(dir_fd, entry->d_name,
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (child_fd < 0)
            continue;

        char *child_path = target_join_path(path, entry->d_name);
        if (child_path == NULL) {
            close(child_fd);
            result = -1;
            break;
        }

        if (target_walk_directory(child_fd, child_path, exts, ext_count,
                                  list) < 0) {
            free(child_path);
            result = -1;
            break;
        }
        free(child_path);
    }

    closedir(dir);
    return result;
}

static char *target_expand_home(const char *path)
{
    if (path[0] != '~')
        return strdup(path);

    const char *home = getenv("HOME");
    if (home == NULL)
        return NULL;

    size_t home_len = strlen(home);
    size_t tail_len = strlen(path + 1);
    if (home_len > SIZE_MAX - tail_len - 1)
        return NULL;

    char *expanded = malloc(home_len + tail_len + 1);
    if (expanded == NULL)
        return NULL;

    memcpy(expanded, home, home_len);
    memcpy(expanded + home_len, path + 1, tail_len + 1);
    return expanded;
}

size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    if (out_paths == NULL)
        return 0;

    *out_paths = NULL;
    if (dirs == NULL || exts == NULL)
        return 0;

    struct target_file_list list = {0};

    for (size_t i = 0; i < dir_count; i++) {
        if (dirs[i] == NULL)
            continue;

        char *root_path = target_expand_home(dirs[i]);
        if (root_path == NULL)
            goto allocation_error;

        int fd = open(root_path, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
        if (fd >= 0 &&
            target_walk_directory(fd, root_path, exts, ext_count, &list) < 0) {
            free(root_path);
            goto allocation_error;
        }
        free(root_path);
    }

    if (list.count != 0)
        *out_paths = list.paths;
    else
        free(list.paths);

    return list.count;

allocation_error:
    for (size_t i = 0; i < list.count; i++)
        free(list.paths[i]);
    free(list.paths);
    return 0;
}