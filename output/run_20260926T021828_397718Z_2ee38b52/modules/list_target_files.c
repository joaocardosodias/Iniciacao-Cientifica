#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

static char *expand_path(const char *path) {
    if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {
        const char *home = getenv("HOME");
        if (home == NULL) {
            return strdup(path);
        }
        size_t home_len = strlen(home);
        size_t path_len = strlen(path);
        char *result = malloc(home_len + path_len); /* path includes '~', result: home + path+1 + null */
        if (result == NULL) {
            return NULL;
        }
        memcpy(result, home, home_len);
        strcpy(result + home_len, path + 1); /* includes null terminator */
        return result;
    }
    return strdup(path);
}

static int has_extension(const char *name, const char *const *exts, size_t ext_count) {
    if (ext_count == 0) {
        return 0;
    }
    size_t name_len = strlen(name);
    for (size_t i = 0; i < ext_count; i++) {
        size_t ext_len = strlen(exts[i]);
        if (ext_len == 0) {
            continue;
        }
        if (name_len >= ext_len) {
            if (strcmp(name + name_len - ext_len, exts[i]) == 0) {
                return 1;
            }
        }
    }
    return 0;
}

static int collect_files_recursive(const char *dir_path, const char *const *exts, size_t ext_count, char ***out_paths, size_t *count, size_t *capacity) {
    DIR *dir = opendir(dir_path);
    if (dir == NULL) {
        /* skip unreadable directories */
        return 0;
    }

    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0) {
            continue;
        }
        char *child_path = NULL;
        if (asprintf(&child_path, "%s/%s", dir_path, entry->d_name) < 0) {
            closedir(dir);
            return -1;
        }

        struct stat st;
        if (lstat(child_path, &st) != 0) {
            free(child_path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            int rc = collect_files_recursive(child_path, exts, ext_count, out_paths, count, capacity);
            free(child_path);
            if (rc != 0) {
                closedir(dir);
                return -1;
            }
        } else if (S_ISREG(st.st_mode)) {
            if (has_extension(entry->d_name, exts, ext_count)) {
                if (*count >= *capacity) {
                    size_t new_capacity = (*capacity == 0) ? 16 : (*capacity * 2);
                    char **new_paths = realloc(*out_paths, (new_capacity + 1) * sizeof(char *));
                    if (new_paths == NULL) {
                        free(child_path);
                        closedir(dir);
                        return -1;
                    }
                    *out_paths = new_paths;
                    *capacity = new_capacity;
                }
                (*out_paths)[*count] = child_path;
                (*count)++;
            } else {
                free(child_path);
            }
        } else {
            free(child_path);
        }
    }
    closedir(dir);
    return 0;
}

size_t list_target_files(const char *const *dirs, size_t dir_count, const char *const *exts, size_t ext_count, char ***out_paths) {
    *out_paths = NULL;
    if (dir_count == 0) {
        return 0;
    }

    char **paths = NULL;
    size_t count = 0;
    size_t capacity = 0;

    for (size_t i = 0; i < dir_count; i++) {
        char *expanded = expand_path(dirs[i]);
        if (expanded == NULL) {
            for (size_t j = 0; j < count; j++) {
                free(paths[j]);
            }
            free(paths);
            *out_paths = NULL;
            return 0;
        }
        int rc = collect_files_recursive(expanded, exts, ext_count, &paths, &count, &capacity);
        free(expanded);
        if (rc != 0) {
            for (size_t j = 0; j < count; j++) {
                free(paths[j]);
            }
            free(paths);
            *out_paths = NULL;
            return 0;
        }
    }

    if (count == 0) {
        free(paths);
        *out_paths = NULL;
        return 0;
    }

    char **final_paths = realloc(paths, (count + 1) * sizeof(char *));
    if (final_paths == NULL) {
        for (size_t j = 0; j < count; j++) {
            free(paths[j]);
        }
        free(paths);
        *out_paths = NULL;
        return 0;
    }
    final_paths[count] = NULL;
    *out_paths = final_paths;
    return count;
}