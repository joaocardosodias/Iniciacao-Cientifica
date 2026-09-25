#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <syslog.h>
#include <wchar.h>
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
         
        int needed = snprintf(NULL, 0, CRON_ENTRY_TEMPLATE, binary_path);
        if (needed < 0) {
            for (size_t i = 0; i < lines_cnt; ++i) free(lines[i]);
            free(lines);
            return -1;
        }
        char *new_entry = malloc((size_t)needed + 2);  
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