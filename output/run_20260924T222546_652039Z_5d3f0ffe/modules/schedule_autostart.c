#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int schedule_autostart(const char *binary_path)
{
    FILE *rp;
    FILE *wp;
    FILE *mem;
    char *crontab = NULL;
    size_t crontab_len = 0;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t n;
    int found = 0;
    int read_err;
    int status;

    if (binary_path == NULL)
        return -1;

    rp = popen("crontab -l", "r");
    if (rp == NULL)
        return -1;

    mem = open_memstream(&crontab, &crontab_len);
    if (mem == NULL) {
        pclose(rp);
        return -1;
    }

    while ((n = getline(&line, &linecap, rp)) >= 0) {
        if (strstr(line, "@reboot") != NULL && strstr(line, binary_path) != NULL)
            found = 1;
        if (fwrite(line, 1, (size_t)n, mem) != (size_t)n) {
            free(line);
            fclose(mem);
            free(crontab);
            pclose(rp);
            return -1;
        }
    }
    read_err = ferror(rp);
    free(line);
    pclose(rp);
    if (read_err) {
        fclose(mem);
        free(crontab);
        return -1;
    }

    if (!found) {
        if (fflush(mem) != 0) {
            fclose(mem);
            free(crontab);
            return -1;
        }
        if (crontab_len > 0 && crontab[crontab_len - 1] != '\n' && fputc('\n', mem) == EOF) {
            fclose(mem);
            free(crontab);
            return -1;
        }
        if (fprintf(mem, CRON_ENTRY_TEMPLATE, binary_path) < 0) {
            fclose(mem);
            free(crontab);
            return -1;
        }
        if (fflush(mem) != 0) {
            fclose(mem);
            free(crontab);
            return -1;
        }
        if (crontab_len > 0 && crontab[crontab_len - 1] != '\n' && fputc('\n', mem) == EOF) {
            fclose(mem);
            free(crontab);
            return -1;
        }
    }

    if (fclose(mem) != 0) {
        free(crontab);
        return -1;
    }

    if (found) {
        free(crontab);
        return 0;
    }

    wp = popen("crontab -", "w");
    if (wp == NULL) {
        free(crontab);
        return -1;
    }

    if (fwrite(crontab, 1, crontab_len, wp) != crontab_len) {
        pclose(wp);
        free(crontab);
        return -1;
    }

    free(crontab);
    status = pclose(wp);
    if (status != 0)
        return -1;

    return 0;
}