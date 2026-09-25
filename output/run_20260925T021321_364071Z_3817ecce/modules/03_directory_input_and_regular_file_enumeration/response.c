#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

/* Public function: enumerates regular files in a directory and prints their names.
 * Parameters:
 *   dir_path - null‑terminated string containing the absolute or relative path to the directory.
 * Returns:
 *   0 on success, non‑zero on any error.
 */
int directory_input_and_regular_file_enumeration(const char *dir_path)
{
    DIR *d;
    struct dirent *entry;
    char full_path[PATH_MAX];
    struct stat st;
    int ret = 0;

    if (dir_path == NULL) {
        fprintf(stderr, "Error: directory path is NULL\n");
        return 1;
    }

    d = opendir(dir_path);
    if (d == NULL) {
        fprintf(stderr, "Error opening directory \"%s\": %s\n", dir_path, strerror(errno));
        return 2;
    }

    while ((entry = readdir(d)) != NULL) {
        /* Skip "." and ".." entries */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        /* Build full path for stat */
        if (snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name) >= (int)sizeof(full_path)) {
            fprintf(stderr, "Path length overflow for entry \"%s\"\n", entry->d_name);
            ret = 3;
            break;
        }

        if (lstat(full_path, &st) != 0) {
            fprintf(stderr, "lstat failed for \"%s\": %s\n", full_path, strerror(errno));
            ret = 4;
            break;
        }

        if (S_ISREG(st.st_mode)) {
            /* Print the file name (full path) */
            if (printf("%s\n", full_path) < 0) {
                fprintf(stderr, "Failed to write output for \"%s\"\n", full_path);
                ret = 5;
                break;
            }
        }
        /* Non‑regular files are ignored */
    }

    closedir(d);
    return ret;
}