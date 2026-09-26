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

int schedule_autostart(const char *binary_path) {
    if (!binary_path) {
        return -1;
    }

    FILE *in = popen("crontab -l", "r");
    if (!in) {
        return -1;
    }

    char *crontab_data = NULL;
    size_t crontab_size = 0;
    size_t crontab_len = 0;
    int already_present = 0;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t linelen;

    while ((linelen = getline(&line, &linecap, in)) != -1) {
        if (!already_present &&
            strstr(line, "@reboot") != NULL &&
            strstr(line, binary_path) != NULL) {
            already_present = 1;
        }
        if (crontab_len + (size_t)linelen + 1 > crontab_size) {
            size_t new_size = crontab_size ? crontab_size * 2 : 4096;
            while (new_size < crontab_len + (size_t)linelen + 1) {
                new_size *= 2;
            }
            char *tmp = realloc(crontab_data, new_size);
            if (!tmp) {
                free(line);
                free(crontab_data);
                pclose(in);
                return -1;
            }
            crontab_data = tmp;
            crontab_size = new_size;
        }
        memcpy(crontab_data + crontab_len, line, (size_t)linelen);
        crontab_len += (size_t)linelen;
    }

    free(line);
    int rc = pclose(in);
    if (rc == -1) {
        free(crontab_data);
        return -1;
    }

    if (already_present) {
        free(crontab_data);
        return 0;
    }

    FILE *out = popen("crontab -", "w");
    if (!out) {
        free(crontab_data);
        return -1;
    }

    if (crontab_data && crontab_len > 0) {
        if (fwrite(crontab_data, 1, crontab_len, out) != crontab_len) {
            free(crontab_data);
            pclose(out);
            return -1;
        }
    }

    if (fprintf(out, CRON_ENTRY_TEMPLATE, binary_path) < 0) {
        free(crontab_data);
        pclose(out);
        return -1;
    }

    free(crontab_data);
    rc = pclose(out);
    if (rc == -1) {
        return -1;
    }
    return 0;
}