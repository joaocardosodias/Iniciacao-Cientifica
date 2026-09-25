#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int schedule_autostart(const char *binary_path)
{
    if (!binary_path)
        return -1;

    char **lines = NULL;
    size_t nlines = 0;
    size_t cap = 0;
    int found = 0;

    FILE *rp = popen("crontab -l", "r");
    if (rp) {
        char *line = NULL;
        size_t len = 0;
        ssize_t r;
        while ((r = getline(&line, &len, rp)) != -1) {
            if (strstr(line, "@reboot") && strstr(line, binary_path))
                found = 1;

            if (nlines == cap) {
                size_t ncap = cap ? cap * 2 : 16;
                char **tmp = realloc(lines, ncap * sizeof(*lines));
                if (!tmp) {
                    free(line);
                    for (size_t i = 0; i < nlines; i++)
                        free(lines[i]);
                    free(lines);
                    pclose(rp);
                    return -1;
                }
                lines = tmp;
                cap = ncap;
            }
            char *copy = strdup(line);
            if (!copy) {
                free(line);
                for (size_t i = 0; i < nlines; i++)
                    free(lines[i]);
                free(lines);
                pclose(rp);
                return -1;
            }
            lines[nlines++] = copy;
        }
        free(line);
        pclose(rp);
    }

    if (found) {
        for (size_t i = 0; i < nlines; i++)
            free(lines[i]);
        free(lines);
        return 0;
    }

    FILE *wp = popen("crontab -", "w");
    if (!wp) {
        for (size_t i = 0; i < nlines; i++)
            free(lines[i]);
        free(lines);
        return -1;
    }

    int err = 0;
    for (size_t i = 0; i < nlines; i++) {
        if (fputs(lines[i], wp) == EOF) {
            err = 1;
            break;
        }
        size_t l = strlen(lines[i]);
        if (l == 0 || lines[i][l - 1] != '\n') {
            if (fputc('\n', wp) == EOF) {
                err = 1;
                break;
            }
        }
    }

    if (!err) {
        if (fprintf(wp, CRON_ENTRY_TEMPLATE, binary_path) < 0)
            err = 1;
        else if (fputc('\n', wp) == EOF)
            err = 1;
    }

    int status = pclose(wp);

    for (size_t i = 0; i < nlines; i++)
        free(lines[i]);
    free(lines);

    if (err || status == -1)
        return -1;

    return 0;
}