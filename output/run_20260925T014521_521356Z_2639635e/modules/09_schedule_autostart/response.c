#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int schedule_autostart(const char *binary_path)
{
    if (!binary_path)
        return -1;

    FILE *fp = popen("crontab -l", "r");
    if (!fp)
        return -1;

    char *crontab = NULL;
    size_t crontab_sz = 0;
    size_t crontab_cap = 0;
    int found = 0;
    char line[4096];

    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, "@reboot") && strstr(line, binary_path))
            found = 1;

        size_t len = strlen(line);
        if (crontab_sz + len + 1 > crontab_cap) {
            size_t new_cap = crontab_cap ? crontab_cap * 2 : 1024;
            while (new_cap < crontab_sz + len + 1)
                new_cap *= 2;
            char *tmp = realloc(crontab, new_cap);
            if (!tmp) {
                free(crontab);
                pclose(fp);
                return -1;
            }
            crontab = tmp;
            crontab_cap = new_cap;
        }
        memcpy(crontab + crontab_sz, line, len);
        crontab_sz += len;
        crontab[crontab_sz] = '\0';
    }

    pclose(fp);

    if (found) {
        free(crontab);
        return 0;
    }

    char new_line[1024];
    int n = snprintf(new_line, sizeof(new_line), CRON_ENTRY_TEMPLATE, binary_path);
    if (n < 0 || (size_t)n >= sizeof(new_line))
        return -1;

    /* Ensure the new entry ends with a newline */
    int needs_nl = (new_line[n - 1] != '\n');
    size_t add_len = n + (needs_nl ? 1 : 0);

    if (crontab_sz + add_len + 1 > crontab_cap) {
        size_t new_cap = crontab_cap ? crontab_cap * 2 : 1024;
        while (new_cap < crontab_sz + add_len + 1)
            new_cap *= 2;
        char *tmp = realloc(crontab, new_cap);
        if (!tmp) {
            free(crontab);
            return -1;
        }
        crontab = tmp;
        crontab_cap = new_cap;
    }

    memcpy(crontab + crontab_sz, new_line, n);
    crontab_sz += n;
    if (needs_nl) {
        crontab[crontab_sz++] = '\n';
    }
    crontab[crontab_sz] = '\0';

    FILE *fpw = popen("crontab -", "w");
    if (!fpw) {
        free(crontab);
        return -1;
    }

    size_t written = fwrite(crontab, 1, crontab_sz, fpw);
    int rc = pclose(fpw);
    free(crontab);

    if (written != crontab_sz || rc != 0)
        return -1;

    return 0;
}