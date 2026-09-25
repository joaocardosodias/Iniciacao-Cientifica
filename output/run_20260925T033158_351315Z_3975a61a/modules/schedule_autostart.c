#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "config.h"

static int contains_reboot_and_path(const char *line, const char *path)
{
    return (strstr(line, "@reboot") != NULL && strstr(line, path) != NULL);
}

int schedule_autostart(const char *binary_path)
{
    if (!binary_path) {
        errno = EINVAL;
        return -1;
    }

    FILE *rp = popen("crontab -l", "r");
    if (!rp) {
        return -1;
    }

    char *crontab = NULL;
    size_t crontab_size = 0;
    size_t crontab_len = 0;
    int found = 0;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t linelen;

    while ((linelen = getline(&line, &linecap, rp)) != -1) {
        if (!found && contains_reboot_and_path(line, binary_path)) {
            found = 1;
        }
        if (crontab_len + (size_t)linelen + 1 > crontab_size) {
            size_t new_size = crontab_size ? crontab_size * 2 : 1024;
            while (new_size < crontab_len + (size_t)linelen + 1) {
                new_size *= 2;
            }
            char *tmp = realloc(crontab, new_size);
            if (!tmp) {
                free(crontab);
                free(line);
                pclose(rp);
                return -1;
            }
            crontab = tmp;
            crontab_size = new_size;
        }
        memcpy(crontab + crontab_len, line, (size_t)linelen);
        crontab_len += (size_t)linelen;
    }

    free(line);
    pclose(rp);

    if (!found) {
        char entry[1024];
        int n = snprintf(entry, sizeof(entry), CRON_ENTRY_TEMPLATE "\n", binary_path);
        if (n < 0 || (size_t)n >= sizeof(entry)) {
            free(crontab);
            return -1;
        }
        size_t needed = crontab_len + (size_t)n + 1;
        if (needed > crontab_size) {
            char *tmp = realloc(crontab, needed);
            if (!tmp) {
                free(crontab);
                return -1;
            }
            crontab = tmp;
            crontab_size = needed;
        }
        memcpy(crontab + crontab_len, entry, (size_t)n);
        crontab_len += (size_t)n;
    }

    FILE *wp = popen("crontab -", "w");
    if (!wp) {
        free(crontab);
        return -1;
    }

    if (crontab_len > 0) {
        if (fwrite(crontab, 1, crontab_len, wp) != crontab_len) {
            free(crontab);
            pclose(wp);
            return -1;
        }
    }

    free(crontab);
    int rc = pclose(wp);
    return (rc == 0) ? 0 : -1;
}