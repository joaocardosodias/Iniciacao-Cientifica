#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <dirent.h>
#include <sys/stat.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>

/*
 * Helper function to process a directory recursively.
 * Scans all entries, recursively enters subdirectories,
 * and removes regular files with extensions .bak, .backup, .old.
 */
static void process_directory(const char *dir_path) {
    DIR *dir = opendir(dir_path);
    if (!dir) {
        fprintf(stderr, "Error opening directory '%s': %s\n", dir_path, strerror(errno));
        return;
    }

    struct dirent *entry;
    char full_path[PATH_MAX];
    struct stat st;

    while ((entry = readdir(dir)) != NULL) {
        // Skip current and parent directory entries
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        // Build full path
        int len = snprintf(full_path, sizeof(full_path), "%s/%s", dir_path, entry->d_name);
        if (len < 0 || (size_t)len >= sizeof(full_path)) {
            fprintf(stderr, "Path too long: %s/%s\n", dir_path, entry->d_name);
            continue;
        }

        // Get file status
        if (stat(full_path, &st) < 0) {
            fprintf(stderr, "Error stating '%s': %s\n", full_path, strerror(errno));
            continue;
        }

        if (S_ISDIR(st.st_mode)) {
            // Recursive call for subdirectories
            process_directory(full_path);
        } else if (S_ISREG(st.st_mode)) {
            // Check extension for regular files
            const char *ext = strrchr(entry->d_name, '.');
            if (ext) {
                if (strcmp(ext, ".bak") == 0 ||
                    strcmp(ext, ".backup") == 0 ||
                    strcmp(ext, ".old") == 0) {
                    // Attempt deletion
                    if (remove(full_path) != 0) {
                        fprintf(stderr, "Error removing file '%s': %s\n",
                                full_path, strerror(errno));
                    }
                }
            }
        }
    }

    closedir(dir);
}

/*
 * purge_backup_files - Scans predefined directories recursively
 * and removes all files with extensions .bak, .backup, or .old.
 * Handles errors gracefully without interrupting the scan.
 */
void purge_backup_files(void) {
    const char *home = getenv("HOME");
    if (!home) {
        fprintf(stderr, "HOME environment variable not set\n");
        return;
    }

    // List of directories to scan (expand ~ manually)
    const char *dirs[] = {
        "Documentos_Teste",
        "Documentos",
        "Downloads",
        "Imagens",
        NULL  // sentinel for homedir-only; we'll handle /mnt separately
    };

    char path[PATH_MAX];
    size_t home_len = strlen(home);

    // Process directories under $HOME
    for (int i = 0; dirs[i] != NULL; i++) {
        int len = snprintf(path, sizeof(path), "%s/%s", home, dirs[i]);
        if (len < 0 || (size_t)len >= sizeof(path)) {
            fprintf(stderr, "Path too long: %s/%s\n", home, dirs[i]);
            continue;
        }
        process_directory(path);
    }

    // Process /mnt separately (absolute path)
    process_directory("/mnt");
}

/*
 * Example usage of purge_backup_files.
 */
int main(void) {
    purge_backup_files();
    return 0;
}