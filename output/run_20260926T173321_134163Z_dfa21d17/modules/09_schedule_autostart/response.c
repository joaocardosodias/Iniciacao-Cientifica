#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/wait.h>
#include "config.h"

static char *read_crontab(size_t *out_len, int *found, const char *binary_path)
{
    FILE *fp = popen("crontab -l", "r");
    if (!fp) {
        return NULL;
    }

    char *buffer = NULL;
    size_t bufsize = 0;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t nread;
    *found = 0;

    while ((nread = getline(&line, &linecap, fp)) != -1) {
        char *newbuf = realloc(buffer, bufsize + (size_t)nread + 1);
        if (!newbuf) {
            free(buffer);
            free(line);
            pclose(fp);
            return NULL;
        }
        buffer = newbuf;
        memcpy(buffer + bufsize, line, (size_t)nread);
        bufsize += (size_t)nread;
        buffer[bufsize] = '\0';

        if (!*found && strstr(line, "@reboot") && strstr(line, binary_path)) {
            *found = 1;
        }
    }

    free(line);
    pclose(fp);
    *out_len = bufsize;
    return buffer;
}

int schedule_autostart(const char *binary_path)
{
    if (!binary_path) {
        return -1;
    }

    size_t crontab_len = 0;
    int found = 0;
    char *crontab = read_crontab(&crontab_len, &found, binary_path);
    if (crontab == NULL && crontab_len != 0) {
        return -1;
    }

    FILE *wp = popen("crontab -", "w");
    if (!wp) {
        free(crontab);
        return -1;
    }

    if (crontab && crontab_len > 0) {
        if (fwrite(crontab, 1, crontab_len, wp) != crontab_len) {
            free(crontab);
            pclose(wp);
            return -1;
        }
    }

    if (!found) {
        char entry[PATH_MAX + 128];
        int n = snprintf(entry, sizeof(entry), CRON_ENTRY_TEMPLATE, binary_path);
        if (n < 0 || (size_t)n >= sizeof(entry)) {
            free(crontab);
            pclose(wp);
            return -1;
        }
        if (entry[n - 1] != '\n') {
            if ((size_t)n + 1 >= sizeof(entry)) {
                free(crontab);
                pclose(wp);
                return -1;
            }
            entry[n] = '\n';
            entry[n + 1] = '\0';
            n++;
        }
        if (fwrite(entry, 1, (size_t)n, wp) != (size_t)n) {
            free(crontab);
            pclose(wp);
            return -1;
        }
    }

    free(crontab);
    int rc = pclose(wp);
    if (rc == -1) {
        return -1;
    }
    if (WIFEXITED(rc) && WEXITSTATUS(rc) == 0) {
        return 0;
    }
    return -1;
}