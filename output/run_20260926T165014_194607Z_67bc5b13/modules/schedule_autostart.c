#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int schedule_autostart(const char *binary_path) {
    if (!binary_path) {
        return -1;
    }

    FILE *in = popen("crontab -l", "r");
    if (!in) {
        return -1;
    }

    char *content = NULL;
    size_t content_len = 0;
    char line[4096];
    int already = 0;

    while (fgets(line, sizeof(line), in)) {
        if (strstr(line, "@reboot") && strstr(line, binary_path)) {
            already = 1;
        }
        size_t line_len = strlen(line);
        char *tmp = realloc(content, content_len + line_len + 1);
        if (!tmp) {
            free(content);
            pclose(in);
            return -1;
        }
        content = tmp;
        memcpy(content + content_len, line, line_len);
        content_len += line_len;
        content[content_len] = '\0';
    }

    int rc = pclose(in);
    if (rc == -1) {
        free(content);
        return -1;
    }

    if (already) {
        free(content);
        return 0;
    }

    FILE *out = popen("crontab -", "w");
    if (!out) {
        free(content);
        return -1;
    }

    if (content && content_len > 0) {
        if (fwrite(content, 1, content_len, out) != content_len) {
            free(content);
            pclose(out);
            return -1;
        }
    }

    if (content_len == 0 || (content && content[content_len - 1] != '\n')) {
        if (fputc('\n', out) == EOF) {
            free(content);
            pclose(out);
            return -1;
        }
    }

    char entry[4096];
    int n = snprintf(entry, sizeof(entry), CRON_ENTRY_TEMPLATE, binary_path);
    if (n < 0 || (size_t)n >= sizeof(entry)) {
        free(content);
        pclose(out);
        return -1;
    }

    if (fwrite(entry, 1, (size_t)n, out) != (size_t)n) {
        free(content);
        pclose(out);
        return -1;
    }
    if (fputc('\n', out) == EOF) {
        free(content);
        pclose(out);
        return -1;
    }

    int rc2 = pclose(out);
    free(content);
    if (rc2 == -1) {
        return -1;
    }

    return 0;
}