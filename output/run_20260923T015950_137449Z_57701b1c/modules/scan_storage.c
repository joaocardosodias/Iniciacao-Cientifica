#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <limits.h>
#include <errno.h>

/* Helper to expand ~ to home directory */
static char* expand_path(const char* path) {
    if (path[0] == '~' && (path[1] == '/' || path[1] == '\0')) {
        const char* home = getenv("HOME");
        if (home == NULL) return NULL;
        size_t home_len = strlen(home);
        size_t path_len = strlen(path);
        char* result = malloc(home_len + path_len); /* path_len includes ~ */
        if (result == NULL) return NULL;
        strcpy(result, home);
        if (path[1] == '/')
            strcat(result, path + 1); /* skip ~ and / */
        else
            strcat(result, ""); /* just home */
        return result;
    }
    return strdup(path);
}

/* Check if filename ends with one of the given extensions (case-insensitive) */
static int has_valid_extension(const char* name) {
    const char* exts[] = {
        ".xlsx", ".docx", ".pdf", ".txt", ".csv",
        ".jpg",  ".png",  ".db",  ".backup", ".psd", ".zip", ".rar"
    };
    size_t num_exts = sizeof(exts) / sizeof(exts[0]);
    size_t name_len = strlen(name);
    for (size_t i = 0; i < num_exts; ++i) {
        size_t ext_len = strlen(exts[i]);
        if (name_len < ext_len) continue;
        /* case-insensitive comparison */
        if (strcasecmp(name + name_len - ext_len, exts[i]) == 0)
            return 1;
    }
    return 0;
}

/* Recursive directory scanning function.
   Uses a dynamic array for results.
   'results' and 'count' and 'capacity' are passed by reference.
   'base' is the full path of the current directory being scanned.
   Returns 0 on success, -1 on allocation failure.
*/
static int scan_dir(const char* dir_path, char*** results, size_t* count, size_t* capacity) {
    DIR* dir = opendir(dir_path);
    if (dir == NULL) {
        /* Silently ignore inaccessible directories */
        return 0;
    }

    struct dirent* entry;
    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        /* Build full path */
        size_t dir_len = strlen(dir_path);
        size_t name_len = strlen(entry->d_name);
        /* +2 for potential slash and null terminator */
        char* full_path = malloc(dir_len + name_len + 2);
        if (full_path == NULL) {
            closedir(dir);
            return -1; /* allocation failure */
        }
        strcpy(full_path, dir_path);
        if (dir_len > 0 && dir_path[dir_len - 1] != '/')
            strcat(full_path, "/");
        strcat(full_path, entry->d_name);

        struct stat st;
        /* Use lstat to avoid following symlinks */
        if (lstat(full_path, &st) != 0) {
            free(full_path);
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            /* Recursively scan subdirectory */
            /* Avoid deep recursion by using static depth limit, but we go deep enough */
            int ret = scan_dir(full_path, results, count, capacity);
            free(full_path);
            if (ret != 0) {
                closedir(dir);
                return -1;
            }
        } else if (S_ISREG(st.st_mode)) {
            /* Regular file: check extension */
            if (has_valid_extension(entry->d_name)) {
                /* Add to results, expanding if needed */
                if (*count >= *capacity) {
                    size_t new_cap = (*capacity == 0) ? 16 : *capacity * 2;
                    char** new_results = realloc(*results, new_cap * sizeof(char*));
                    if (new_results == NULL) {
                        free(full_path);
                        closedir(dir);
                        return -1;
                    }
                    *results = new_results;
                    *capacity = new_cap;
                }
                (*results)[*count] = full_path;
                (*count)++;
            } else {
                free(full_path);
            }
        } else {
            free(full_path);
        }
    }
    closedir(dir);
    return 0;
}

char** scan_storage(const char* base_paths[], int num_paths, size_t* out_count) {
    if (out_count == NULL) return NULL;
    *out_count = 0;

    char** results = NULL;
    size_t count = 0;
    size_t capacity = 0;

    for (int i = 0; i < num_paths; ++i) {
        char* expanded = expand_path(base_paths[i]);
        if (expanded == NULL) continue;

        /* Verify it's a directory before scanning */
        struct stat st;
        if (stat(expanded, &st) != 0 || !S_ISDIR(st.st_mode)) {
            free(expanded);
            continue;
        }

        /* Use a duplicate of expanded since we'll reuse it */
        char* dir_copy = strdup(expanded);
        free(expanded);
        if (dir_copy == NULL) {
            /* Free already allocated resources */
            for (size_t j = 0; j < count; ++j)
                free(results[j]);
            free(results);
            *out_count = 0;
            return NULL;
        }

        int ret = scan_dir(dir_copy, &results, &count, &capacity);
        free(dir_copy);
        if (ret != 0) {
            /* Allocation failure during scan */
            for (size_t j = 0; j < count; ++j)
                free(results[j]);
            free(results);
            *out_count = 0;
            return NULL;
        }
    }

    *out_count = count;
    return results;
}

#ifdef TEST_MAIN
int main() {
    const char* dirs[] = {
        "~/Documentos_Teste", "~/Documentos", "~/Downloads", "~/Imagens", "/mnt"
    };
    size_t count;
    char** files = scan_storage(dirs, 5, &count);
    if (files == NULL) {
        printf("No files found or error occurred.\n");
        return 1;
    }
    printf("Found %zu files:\n", count);
    for (size_t i = 0; i < count; ++i) {
        printf("%s\n", files[i]);
        free(files[i]);
    }
    free(files);
    return 0;
}
#endif