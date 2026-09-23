#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <unistd.h>
#include <errno.h>

/*
 * register_service - Add a @reboot cron entry for the current executable
 *
 * Arguments:
 *   argv0 - first argument of main (path to executable)
 *
 * Returns:
 *   0 on success, -1 on error (error message printed to stderr)
 *
 * Steps:
 *   1. Resolve absolute path of the executable.
 *   2. Build the cron line: "@reboot <path>".
 *   3. Read existing crontab with popen("crontab -l", "r").
 *   4. If the line already exists, do nothing and return 0.
 *   5. Otherwise, append the line and write back via popen("crontab -", "w").
 */
int register_service(const char *argv0) {
    char *path = NULL;          // absolute path of executable
    char *line = NULL;          // cron line to add
    char *content = NULL;       // entire current crontab content
    size_t content_len = 0;     // length of content (excluding null)
    size_t content_cap = 0;     // allocated capacity
    int ret = -1;               // return value
    FILE *fp = NULL;

    /* ---------- Step 1: Obtain absolute path ---------- */
    if (argv0 != NULL) {
        // Use realpath with automatic allocation (GNU extension)
        path = realpath(argv0, NULL);
        if (path == NULL) {
            // Fallback: read from /proc/self/exe
            char buf[PATH_MAX];
            ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
            if (n > 0) {
                buf[n] = '\0';
                path = strdup(buf);
            }
        }
    }
    // If argv0 was NULL or both methods failed, try /proc/self/exe directly
    if (path == NULL) {
        char buf[PATH_MAX];
        ssize_t n = readlink("/proc/self/exe", buf, sizeof(buf) - 1);
        if (n > 0) {
            buf[n] = '\0';
            path = strdup(buf);
        }
    }

    if (path == NULL) {
        fprintf(stderr, "register_service: cannot determine executable path (errno=%d)\n", errno);
        goto cleanup;
    }

    /* ---------- Step 2: Build cron line ---------- */
    // Check if path contains spaces or other special characters that need quoting
    const char *special = " \t\n";
    int needs_quoting = (strpbrk(path, special) != NULL);

    // Format: "@reboot /path" or "@reboot \"/path\""
    const char *fmt = needs_quoting ? "@reboot \"%s\"\n" : "@reboot %s\n";
    int line_len = snprintf(NULL, 0, fmt, path);
    if (line_len < 0) {
        fprintf(stderr, "register_service: snprintf failed\n");
        goto cleanup;
    }
    line = malloc(line_len + 1);
    if (line == NULL) {
        fprintf(stderr, "register_service: malloc failed\n");
        goto cleanup;
    }
    snprintf(line, line_len + 1, fmt, path);

    /* ---------- Step 3: Read current crontab ---------- */
    fp = popen("crontab -l", "r");
    if (fp == NULL) {
        fprintf(stderr, "register_service: popen(crontab -l) failed (errno=%d)\n", errno);
        goto cleanup;
    }

    // Read all lines using getline into a dynamic buffer
    char *line_buf = NULL;
    size_t line_buf_size = 0;
    ssize_t nread;
    while ((nread = getline(&line_buf, &line_buf_size, fp)) != -1) {
        // Append line to content buffer
        size_t needed = content_len + nread + 1; // +1 for null terminator
        if (needed > content_cap) {
            size_t new_cap = content_cap ? content_cap * 2 : 4096;
            while (new_cap < needed) new_cap *= 2;
            char *new_content = realloc(content, new_cap);
            if (new_content == NULL) {
                fprintf(stderr, "register_service: realloc failed\n");
                free(line_buf);
                pclose(fp);
                fp = NULL;
                goto cleanup;
            }
            content = new_content;
            content_cap = new_cap;
        }
        memcpy(content + content_len, line_buf, nread);
        content_len += nread;
    }
    free(line_buf); // line_buf may have been allocated by getline

    // Close and check exit status
    int status = pclose(fp);
    fp = NULL;
    if (status != 0) {
        // If we read no content, treat as empty crontab (not an error)
        if (content_len == 0) {
            // Nothing to do, content remains empty
        } else {
            // Error with non-empty output (unlikely)
            fprintf(stderr, "register_service: crontab -l returned non-zero with content, aborting\n");
            goto cleanup;
        }
    }

    // Ensure content is null-terminated (may already be empty)
    if (content == NULL) {
        content = strdup("");
        if (content == NULL) {
            fprintf(stderr, "register_service: strdup failed\n");
            goto cleanup;
        }
        content_cap = 1;
        content_len = 0;
    } else {
        content[content_len] = '\0';
    }

    /* ---------- Step 4: Check if line already exists ---------- */
    if (strstr(content, line) != NULL) {
        // Line already present, success without changes
        ret = 0;
        goto cleanup;
    }

    /* ---------- Step 5: Add line to crontab ---------- */
    // Ensure there is a newline before appending (if content not empty and last char not newline)
    if (content_len > 0 && content[content_len - 1] != '\n') {
        // This should rarely happen, but handle gracefully
        content_len++; // we are going to append a newline
        if (content_len >= content_cap) {
            char *new_content = realloc(content, content_len + 1);
            if (new_content == NULL) {
                fprintf(stderr, "register_service: realloc failed\n");
                goto cleanup;
            }
            content = new_content;
        }
        content[content_len - 1] = '\n';
        content[content_len] = '\0';
    }

    // Append the new line
    size_t new_len = content_len + strlen(line);
    if (new_len + 1 > content_cap) {
        char *new_content = realloc(content, new_len + 1);
        if (new_content == NULL) {
            fprintf(stderr, "register_service: realloc failed\n");
            goto cleanup;
        }
        content = new_content;
    }
    strcat(content, line);
    content_len = new_len;

    // Write to crontab via popen
    fp = popen("crontab -", "w");
    if (fp == NULL) {
        fprintf(stderr, "register_service: popen(crontab -) failed (errno=%d)\n", errno);
        goto cleanup;
    }
    if (fputs(content, fp) == EOF) {
        fprintf(stderr, "register_service: fputs failed\n");
        pclose(fp);
        fp = NULL;
        goto cleanup;
    }
    status = pclose(fp);
    fp = NULL;
    if (status != 0) {
        fprintf(stderr, "register_service: crontab - returned non-zero exit status\n");
        goto cleanup;
    }

    ret = 0; // success

cleanup:
    free(path);
    free(line);
    free(content);
    if (fp != NULL) pclose(fp);
    return ret;
}

/*
 * Example usage: call register_service with argv[0].
 * If successful, the program's own executable will be added to crontab for @reboot.
 * Run twice to verify no duplication.
 */
int main(int argc, char *argv[]) {
    if (argc >= 1) {
        int res = register_service(argv[0]);
        if (res == 0) {
            printf("Service registered successfully.\n");
        } else {
            printf("Failed to register service.\n");
            return 1;
        }
    } else {
        fprintf(stderr, "No argv[0] available\n");
        return 1;
    }
    return 0;
}