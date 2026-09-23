#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>

/*
 * Recursively scans the directory at 'dirpath' and removes all regular files
 * whose extension (after the last '.') is exactly "bak", "backup" or "old".
 * Symbolic links are ignored (not followed). Entries "." and ".." are skipped.
 * Allocation is controlled; memory is freed on error or completion.
 */
static void recursive_clean(const char *dirpath) {
    DIR *dp = opendir(dirpath);
    if (!dp)
        return; /* Cannot open directory – silently ignore */

    struct dirent *entry;
    char *fullpath = malloc(PATH_MAX);
    if (!fullpath) {
        closedir(dp);
        return;
    }

    while ((entry = readdir(dp)) != NULL) {
        /* Skip current and parent directory entries */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        /* Build full path */
        int len = snprintf(fullpath, PATH_MAX, "%s/%s", dirpath, entry->d_name);
        if (len < 0 || len >= PATH_MAX) {
            /* Path too long – skip this entry */
            continue;
        }

        struct stat st;
        /* Use lstat to avoid following symbolic links */
        if (lstat(fullpath, &st) != 0)
            continue;

        /* Ignore symbolic links (do not process them) */
        if (S_ISLNK(st.st_mode))
            continue;

        if (S_ISDIR(st.st_mode)) {
            /* Recurse into subdirectories */
            recursive_clean(fullpath);
        } else if (S_ISREG(st.st_mode)) {
            /* Check file extension */
            const char *dot = strrchr(entry->d_name, '.');
            if (dot) {
                dot++; /* Skip the dot itself */
                if (strcmp(dot, "bak") == 0 ||
                    strcmp(dot, "backup") == 0 ||
                    strcmp(dot, "old") == 0) {
                    remove(fullpath); /* Ignore deletion failures */
                }
            }
        }
    }

    free(fullpath);
    closedir(dp);
}

/*
 * Cleans backup files from a predefined set of directories.
 * Directories: ~/Documentos_Teste, ~/Documentos, ~/Downloads, ~/Imagens, /mnt
 * Home directory is expanded from the HOME environment variable.
 */
void cleanup_backups(void) {
    const char *home = getenv("HOME");
    if (!home)
        home = ""; /* Fallback – empty string, will produce invalid paths, but safe */

    /* List of target base directories (some with ~/ prefix, others absolute) */
    const char *bases[] = {
        "Documentos_Teste",
        "Documentos",
        "Downloads",
        "Imagens",
        "/mnt"
    };
    const int num_bases = sizeof(bases) / sizeof(bases[0]);

    char *path = malloc(PATH_MAX);
    if (!path)
        return;

    for (int i = 0; i < num_bases; i++) {
        /* For the first four entries, prepend home directory */
        if (i < 4) {
            int len = snprintf(path, PATH_MAX, "%s/%s", home, bases[i]);
            if (len < 0 || len >= PATH_MAX)
                continue; /* Path overflow – skip */
        } else {
            /* Last entry (/mnt) is absolute */
            strncpy(path, bases[i], PATH_MAX - 1);
            path[PATH_MAX - 1] = '\0';
        }
        recursive_clean(path);
    }

    free(path);
}