#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>

#include "config.h"

static int write_all(FILE *stream, const char *buf, size_t len)
{
    return fwrite(buf, 1, len, stream) == len ? 0 : -1;
}

int schedule_autostart(const char *binary_path)
{
    FILE *read_fp;
    FILE *write_fp;
    char *content;
    size_t content_len;
    size_t content_cap;
    char *line;
    size_t line_cap;
    ssize_t line_len;
    int already_present;
    char *entry;
    int entry_len;
    int status;

    if (binary_path == NULL || binary_path[0] == '\0')
        return -1;

    content = NULL;
    content_len = 0;
    content_cap = 0;
    line = NULL;
    line_cap = 0;
    already_present = 0;

    read_fp = popen("crontab -l", "r");
    if (read_fp == NULL)
        return -1;

    while ((line_len = getline(&line, &line_cap, read_fp)) != -1) {
        size_t needed = content_len + (size_t)line_len + 1;

        if (!already_present &&
            strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL)
            already_present = 1;

        if (needed > content_cap) {
            size_t new_cap = content_cap == 0 ? 4096 : content_cap;
            char *grown;

            while (new_cap < needed)
                new_cap *= 2;
            grown = realloc(content, new_cap);
            if (grown == NULL) {
                free(line);
                free(content);
                pclose(read_fp);
                return -1;
            }
            content = grown;
            content_cap = new_cap;
        }
        memcpy(content + content_len, line, (size_t)line_len);
        content_len += (size_t)line_len;
        content[content_len] = '\0';
    }

    free(line);

    if (ferror(read_fp)) {
        pclose(read_fp);
        free(content);
        return -1;
    }

    /* "crontab -l" exits non-zero when the user has no crontab yet;
       that is expected, so its exit status is not treated as fatal */
    pclose(read_fp);

    if (already_present) {
        free(content);
        return 0;
    }

    entry_len = snprintf(NULL, 0, CRON_ENTRY_TEMPLATE, binary_path);
    if (entry_len < 0) {
        free(content);
        return -1;
    }
    entry = malloc((size_t)entry_len + 1);
    if (entry == NULL) {
        free(content);
        return -1;
    }
    snprintf(entry, (size_t)entry_len + 1, CRON_ENTRY_TEMPLATE, binary_path);

    write_fp = popen("crontab -", "w");
    if (write_fp == NULL) {
        free(entry);
        free(content);
        return -1;
    }

    if (content_len > 0 && write_all(write_fp, content, content_len) != 0) {
        pclose(write_fp);
        free(entry);
        free(content);
        return -1;
    }

    if (content_len > 0 && content[content_len - 1] != '\n' &&
        fputc('\n', write_fp) == EOF) {
        pclose(write_fp);
        free(entry);
        free(content);
        return -1;
    }

    if (write_all(write_fp, entry, (size_t)entry_len) != 0) {
        pclose(write_fp);
        free(entry);
        free(content);
        return -1;
    }

    if (entry_len == 0 || entry[entry_len - 1] != '\n') {
        if (fputc('\n', write_fp) == EOF) {
            pclose(write_fp);
            free(entry);
            free(content);
            return -1;
        }
    }

    free(entry);
    free(content);

    status = pclose(write_fp);
    if (status == -1 || !WIFEXITED(status) || WEXITSTATUS(status) != 0)
        return -1;

    return 0;
}