#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int schedule_autostart(const char *binary_path)
{
    if (!binary_path)
        return -1;

    /* Read existing crontab */
    FILE *in = popen("crontab -l", "r");
    if (!in)
        return -1;

    size_t bufsize = 1024;
    size_t len = 0;
    char *buf = malloc(bufsize);
    if (!buf) {
        pclose(in);
        return -1;
    }

    int already_present = 0;
    char line[1024];
    while (fgets(line, sizeof(line), in)) {
        /* Check for existing entry */
        if (!already_present &&
            strstr(line, "@reboot") && strstr(line, binary_path))
            already_present = 1;

        size_t line_len = strlen(line);
        if (len + line_len + 1 > bufsize) {
            size_t newsize = bufsize * 2;
            while (newsize < len + line_len + 1)
                newsize *= 2;
            char *tmp = realloc(buf, newsize);
            if (!tmp) {
                free(buf);
                pclose(in);
                return -1;
            }
            buf = tmp;
            bufsize = newsize;
        }
        memcpy(buf + len, line, line_len);
        len += line_len;
    }
    pclose(in);

    if (!already_present) {
        /* Prepare new cron entry */
        int needed = snprintf(NULL, 0, CRON_ENTRY_TEMPLATE, binary_path);
        if (needed < 0) {
            free(buf);
            return -1;
        }
        size_t entry_len = (size_t)needed;
        char *entry = malloc(entry_len + 2); /* space for optional newline + NUL */
        if (!entry) {
            free(buf);
            return -1;
        }
        snprintf(entry, entry_len + 1, CRON_ENTRY_TEMPLATE, binary_path);
        /* Ensure newline */
        if (entry_len == 0 || entry[entry_len - 1] != '\n') {
            entry[entry_len] = '\n';
            entry[entry_len + 1] = '\0';
            entry_len += 1;
        }

        if (len + entry_len + 1 > bufsize) {
            size_t newsize = bufsize * 2;
            while (newsize < len + entry_len + 1)
                newsize *= 2;
            char *tmp = realloc(buf, newsize);
            if (!tmp) {
                free(entry);
                free(buf);
                return -1;
            }
            buf = tmp;
            bufsize = newsize;
        }
        memcpy(buf + len, entry, entry_len);
        len += entry_len;
        free(entry);
    }

    /* Write back updated crontab */
    FILE *out = popen("crontab -", "w");
    if (!out) {
        free(buf);
        return -1;
    }
    if (len > 0) {
        if (fwrite(buf, 1, len, out) != len) {
            free(buf);
            pclose(out);
            return -1;
        }
    }
    free(buf);
    if (pclose(out) == -1)
        return -1;

    return 0;
}