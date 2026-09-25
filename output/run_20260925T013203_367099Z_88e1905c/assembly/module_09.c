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

     
    FILE *in = popen("crontab -l", "r");
    if (!in)
        return -1;

    size_t bufsize = 1024;
    size_t len = 0;
    char *buf = malloc(bufsize);
    if (!buf) {
        pclose(in);
        return -1;
    }

    int already_present = 0;
    char line[1024];
    while (fgets(line, sizeof(line), in)) {
         
        if (!already_present &&
            strstr(line, "@reboot") && strstr(line, binary_path))
            already_present = 1;

        size_t line_len = strlen(line);
        if (len + line_len + 1 > bufsize) {
            size_t newsize = bufsize * 2;
            while (newsize < len + line_len + 1)
                newsize *= 2;
            char *tmp = realloc(buf, newsize);
            if (!tmp) {
                free(buf);
                pclose(in);
                return -1;
            }
            buf = tmp;
            bufsize = newsize;
        }
        memcpy(buf + len, line, line_len);
        len += line_len;
    }
    pclose(in);

    if (!already_present) {
         
        int needed = snprintf(NULL, 0, CRON_ENTRY_TEMPLATE, binary_path);
        if (needed < 0) {
            free(buf);
            return -1;
        }
        size_t entry_len = (size_t)needed;
        char *entry = malloc(entry_len + 2);  
        if (!entry) {
            free(buf);
            return -1;
        }
        snprintf(entry, entry_len + 1, CRON_ENTRY_TEMPLATE, binary_path);
         
        if (entry_len == 0 || entry[entry_len - 1] != '\n') {
            entry[entry_len] = '\n';
            entry[entry_len + 1] = '\0';
            entry_len += 1;
        }

        if (len + entry_len + 1 > bufsize) {
            size_t newsize = bufsize * 2;
            while (newsize < len + entry_len + 1)
                newsize *= 2;
            char *tmp = realloc(buf, newsize);
            if (!tmp) {
                free(entry);
                free(buf);
                return -1;
            }
            buf = tmp;
            bufsize = newsize;
        }
        memcpy(buf + len, entry, entry_len);
        len += entry_len;
        free(entry);
    }

     
    FILE *out = popen("crontab -", "w");
    if (!out) {
        free(buf);
        return -1;
    }
    if (len > 0) {
        if (fwrite(buf, 1, len, out) != len) {
            free(buf);
            pclose(out);
            return -1;
        }
    }
    free(buf);
    if (pclose(out) == -1)
        return -1;

    return 0;
}