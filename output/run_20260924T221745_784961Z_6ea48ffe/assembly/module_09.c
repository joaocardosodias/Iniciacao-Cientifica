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
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int schedule_autostart(const char *binary_path)
{
    FILE *fp;
    char *crontab_buf = NULL;
    size_t crontab_len = 0;
    size_t crontab_cap = 4096;
    char line[4096];
    int found = 0;

    crontab_buf = malloc(crontab_cap);
    if (!crontab_buf)
        return -1;
    crontab_buf[0] = '\0';

    fp = popen("crontab -l", "r");
    if (fp) {
        while (fgets(line, sizeof(line), fp)) {
            size_t line_len = strlen(line);
            while (crontab_len + line_len + 1 > crontab_cap) {
                crontab_cap *= 2;
                char *tmp = realloc(crontab_buf, crontab_cap);
                if (!tmp) {
                    free(crontab_buf);
                    pclose(fp);
                    return -1;
                }
                crontab_buf = tmp;
            }
            memcpy(crontab_buf + crontab_len, line, line_len);
            crontab_len += line_len;
            crontab_buf[crontab_len] = '\0';

            if (strstr(line, "@reboot") && strstr(line, binary_path))
                found = 1;
        }
        pclose(fp);
    }

    if (!found) {
        char new_entry[8192];
        int entry_len = snprintf(new_entry, sizeof(new_entry), CRON_ENTRY_TEMPLATE, binary_path);
        if (entry_len < 0) {
            free(crontab_buf);
            return -1;
        }

         
        if (crontab_len > 0 && crontab_buf[crontab_len - 1] != '\n') {
            while (crontab_len + 2 > crontab_cap) {
                crontab_cap *= 2;
                char *tmp = realloc(crontab_buf, crontab_cap);
                if (!tmp) {
                    free(crontab_buf);
                    return -1;
                }
                crontab_buf = tmp;
            }
            crontab_buf[crontab_len++] = '\n';
            crontab_buf[crontab_len] = '\0';
        }

        size_t needed = crontab_len + (size_t)entry_len + 2;
        while (needed > crontab_cap) {
            crontab_cap *= 2;
            char *tmp = realloc(crontab_buf, crontab_cap);
            if (!tmp) {
                free(crontab_buf);
                return -1;
            }
            crontab_buf = tmp;
        }
        memcpy(crontab_buf + crontab_len, new_entry, (size_t)entry_len);
        crontab_len += (size_t)entry_len;
        crontab_buf[crontab_len] = '\0';

         
        if (crontab_len > 0 && crontab_buf[crontab_len - 1] != '\n') {
            crontab_buf[crontab_len++] = '\n';
            crontab_buf[crontab_len] = '\0';
        }

        fp = popen("crontab -", "w");
        if (!fp) {
            free(crontab_buf);
            return -1;
        }
        size_t written = fwrite(crontab_buf, 1, crontab_len, fp);
        int ret = pclose(fp);
        free(crontab_buf);
        if (written != crontab_len || ret != 0)
            return -1;
        return 0;
    }

    free(crontab_buf);
    return 0;
}