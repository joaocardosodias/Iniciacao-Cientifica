#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "config.h"

int schedule_autostart(const char *binary_path)
{
    if (!binary_path) {
        errno = EINVAL;
        return -1;
    }

    FILE *in = popen("crontab -l", "r");
    if (!in) {
        return -1;
    }

    char *line = NULL;
    size_t line_cap = 0;
    ssize_t nread;
    char *output = NULL;
    size_t out_len = 0;
    int already = 0;

    while ((nread = getline(&line, &line_cap, in)) != -1) {
        if (!already && strstr(line, "@reboot") && strstr(line, binary_path)) {
            already = 1;
        }
        char *tmp = realloc(output, out_len + (size_t)nread + 1);
        if (!tmp) {
            free(line);
            free(output);
            pclose(in);
            return -1;
        }
        output = tmp;
        memcpy(output + out_len, line, (size_t)nread);
        out_len += (size_t)nread;
        output[out_len] = '\0';
    }

    free(line);
    pclose(in);

    if (!already) {
        char entry[1024];
        int ret = snprintf(entry, sizeof(entry), CRON_ENTRY_TEMPLATE, binary_path);
        if (ret < 0 || (size_t)ret >= sizeof(entry)) {
            free(output);
            return -1;
        }
        size_t entry_len = strlen(entry);
        if (entry_len == 0 || entry[entry_len - 1] != '\n') {
            if (entry_len + 1 >= sizeof(entry)) {
                free(output);
                return -1;
            }
            entry[entry_len] = '\n';
            entry[entry_len + 1] = '\0';
            entry_len++;
        }
        char *tmp = realloc(output, out_len + entry_len + 1);
        if (!tmp) {
            free(output);
            return -1;
        }
        output = tmp;
        memcpy(output + out_len, entry, entry_len);
        out_len += entry_len;
        output[out_len] = '\0';
    }

    FILE *out = popen("crontab -", "w");
    if (!out) {
        free(output);
        return -1;
    }

    if (out_len > 0) {
        if (fwrite(output, 1, out_len, out) != out_len) {
            pclose(out);
            free(output);
            return -1;
        }
    }

    int rc = pclose(out);
    free(output);
    return (rc == 0) ? 0 : -1;
}