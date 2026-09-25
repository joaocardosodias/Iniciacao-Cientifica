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