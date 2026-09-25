#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int schedule_autostart(const char *binary_path)
{
    if (!binary_path) {
        return -1;
    }

    FILE *in = popen("crontab -l", "r");
    if (!in) {
        return -1;
    }

    char **lines = NULL;
    size_t lines_cap = 0;
    size_t lines_cnt = 0;
    char *line = NULL;
    size_t len = 0;
    ssize_t nread;
    int already_present = 0;

    while ((nread = getline(&line, &len, in)) != -1) {
        /* store line */
        if (lines_cnt == lines_cap) {
            size_t new_cap = lines_cap ? lines_cap * 2 : 16;
            char **tmp = realloc(lines, new_cap * sizeof(*tmp));
            if (!tmp) {
                free(line);
                for (size_t i = 0; i < lines_cnt; ++i) free(lines[i]);
                free(lines);
                pclose(in);
                return -1;
            }
            lines = tmp;
            lines_cap = new_cap;
        }
        lines[lines_cnt] = strdup(line);
        if (!lines[lines_cnt]) {
            free(line);
            for (size_t i = 0; i < lines_cnt; ++i) free(lines[i]);
            free(lines);
            pclose(in);
            return -1;
        }
        ++lines_cnt;

        if (!already_present &&
            strstr(line, "@reboot") && strstr(line, binary_path)) {
            already_present = 1;
        }
    }
    free(line);
    pclose(in);
    line = NULL;
    len = 0;

    if (!already_present) {
        /* create new cron entry */
        int needed = snprintf(NULL, 0, CRON_ENTRY_TEMPLATE, binary_path);
        if (needed < 0) {
            for (size_t i = 0; i < lines_cnt; ++i) free(lines[i]);
            free(lines);
            return -1;
        }
        char *new_entry = malloc((size_t)needed + 2); /* for newline and null */
        if (!new_entry) {
            for (size_t i = 0; i < lines_cnt; ++i) free(lines[i]);
            free(lines);
            return -1;
        }
        snprintf(new_entry, (size_t)needed + 1, CRON_ENTRY_TEMPLATE, binary_path);
        new_entry[needed] = '\n';
        new_entry[needed + 1] = '\0';

        if (lines_cnt == lines_cap) {
            size_t new_cap = lines_cap ? lines_cap * 2 : 16;
            char **tmp = realloc(lines, new_cap * sizeof(*tmp));
            if (!tmp) {
                free(new_entry);
                for (size_t i = 0; i < lines_cnt; ++i) free(lines[i]);
                free(lines);
                return -1;
            }
            lines = tmp;
            lines_cap = new_cap;
        }
        lines[lines_cnt++] = new_entry;
    }

    FILE *out = popen("crontab -", "w");
    if (!out) {
        for (size_t i = 0; i < lines_cnt; ++i) free(lines[i]);
        free(lines);
        return -1;
    }

    for (size_t i = 0; i < lines_cnt; ++i) {
        if (fputs(lines[i], out) == EOF) {
            for (size_t j = 0; j < lines_cnt; ++j) free(lines[j]);
            free(lines);
            pclose(out);
            return -1;
        }
        free(lines[i]);
    }
    free(lines);

    int rc = pclose(out);
    if (rc != 0) {
        return -1;
    }

    return 0;
}