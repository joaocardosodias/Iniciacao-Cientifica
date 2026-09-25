#define _GNU_SOURCE
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <dirent.h>
#include <errno.h>

static char *expand_path(const char *path)
{
    if (!path)
        return NULL;
    if (path[0] != '~')
        return strdup(path);
    const char *home = getenv("HOME");
    if (!home)
        return strdup(path);
    size_t home_len = strlen(home);
    const char *rest = path + 1; /* skip '~' */
    size_t rest_len = strlen(rest);
    char *newpath = malloc(home_len + rest_len + 1);
    if (!newpath)
        return NULL;
    memcpy(newpath, home, home_len);
    memcpy(newpath + home_len, rest, rest_len + 1);
    return newpath;
}

static int has_ext(const char *filename, const char *const *exts, size_t ext_count)
{
    size_t fname_len = strlen(filename);
    for (size_t i = 0; i < ext_count; ++i) {
        const char *ext = exts[i];
        size_t ext_len = strlen(ext);
        if (ext_len == 0)
            continue;
        if (fname_len >= ext_len && strcmp(filename + fname_len - ext_len, ext) == 0)
            return 1;
    }
    return 0;
}

static int process_dir(const char *dir,
                       const char *const *exts,
                       size_t ext_count,
                       char ***list_ptr,
                       size_t *count_ptr,
                       size_t *capacity_ptr)
{
    DIR *d = opendir(dir);
    if (!d)
        return 0; /* skip unreadable directories */

    struct dirent *entry;
    while ((entry = readdir(d)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        size_t dir_len = strlen(dir);
        size_t name_len = strlen(entry->d_name);
        char *full = malloc(dir_len + 1 + name_len + 1);
        if (!full) {
            closedir(d);
            return -1;
        }
        memcpy(full, dir, dir_len);
        full[dir_len] = '/';
        memcpy(full + dir_len + 1, entry->d_name, name_len + 1);

        struct stat sb;
        if (lstat(full, &sb) == -1) {
            free(full);
            continue;
        }

        if (S_ISDIR(sb.st_mode)) {
            int rc = process_dir(full, exts, ext_count, list_ptr, count_ptr, capacity_ptr);
            free(full);
            if (rc == -1) {
                closedir(d);
                return -1;
            }
        } else if (S_ISREG(sb.st_mode)) {
            if (has_ext(entry->d_name, exts, ext_count)) {
                if (*count_ptr >= *capacity_ptr) {
                    size_t newcap = (*capacity_ptr) * 2;
                    char **tmp = realloc(*list_ptr, newcap * sizeof(char *));
                    if (!tmp) {
                        free(full);
                        closedir(d);
                        return -1;
                    }
                    *list_ptr = tmp;
                    *capacity_ptr = newcap;
                }
                (*list_ptr)[*count_ptr] = full;
                (*count_ptr)++;
            } else {
                free(full);
            }
        } else {
            free(full);
        }
    }

    closedir(d);
    return 0;
}

size_t list_target_files(const char *const *dirs,
                         size_t dir_count,
                         const char *const *exts,
                         size_t ext_count,
                         char ***out_paths)
{
    if (!out_paths) {
        return 0;
    }
    *out_paths = NULL;

    if (dir_count == 0 || ext_count == 0)
        return 0;

    size_t capacity = 128;
    char **list = malloc(capacity * sizeof(char *));
    if (!list)
        return 0;

    size_t count = 0;

    for (size_t i = 0; i < dir_count; ++i) {
        char *expanded = expand_path(dirs[i]);
        if (!expanded) {
            /* allocation failure: clean up and abort */
            for (size_t j = 0; j < count; ++j)
                free(list[j]);
            free(list);
            return 0;
        }

        int rc = process_dir(expanded, exts, ext_count, &list, &count, &capacity);
        free(expanded);
        if (rc == -1) {
            for (size_t j = 0; j < count; ++j)
                free(list[j]);
            free(list);
            return 0;
        }
    }

    if (count == 0) {
        free(list);
        return 0;
    }

    char **result = realloc(list, (count + 1) * sizeof(char *));
    if (!result) {
        for (size_t j = 0; j < count; ++j)
            free(list[j]);
        free(list);
        return 0;
    }
    result[count] = NULL;
    *out_paths = result;
    return count;
}