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

static int contains_substrings(const char *line, const char *sub1, const char *sub2) {
    return strstr(line, sub1) && strstr(line, sub2);
}

int schedule_autostart(const char *binary_path) {
    if (!binary_path) {
        return -1;
    }

    FILE *in = popen("crontab -l", "r");
    if (!in) {
        return -1;
    }

    char *crontab_content = NULL;
    size_t content_len = 0;
    int already_present = 0;
    char *line = NULL;
    size_t linecap = 0;
    ssize_t linelen;

    while ((linelen = getline(&line, &linecap, in)) != -1) {
        if (!already_present && contains_substrings(line, "@reboot", binary_path)) {
            already_present = 1;
        }
        char *new_content = realloc(crontab_content, content_len + (size_t)linelen + 1);
        if (!new_content) {
            free(crontab_content);
            free(line);
            pclose(in);
            return -1;
        }
        crontab_content = new_content;
        memcpy(crontab_content + content_len, line, (size_t)linelen);
        content_len += (size_t)linelen;
        crontab_content[content_len] = '\0';
    }

    free(line);
    pclose(in);

    if (!already_present) {
        char entry_buffer[4096];
        int entry_len = snprintf(entry_buffer, sizeof(entry_buffer), CRON_ENTRY_TEMPLATE "\n", binary_path);
        if (entry_len < 0 || (size_t)entry_len >= sizeof(entry_buffer)) {
            free(crontab_content);
            return -1;
        }

        char *new_content = realloc(crontab_content, content_len + (size_t)entry_len + 1);
        if (!new_content) {
            free(crontab_content);
            return -1;
        }
        crontab_content = new_content;
        memcpy(crontab_content + content_len, entry_buffer, (size_t)entry_len);
        content_len += (size_t)entry_len;
        crontab_content[content_len] = '\0';
    }

    FILE *out = popen("crontab -", "w");
    if (!out) {
        free(crontab_content);
        return -1;
    }

    if (crontab_content) {
        if (fwrite(crontab_content, 1, content_len, out) != content_len) {
            free(crontab_content);
            pclose(out);
            return -1;
        }
    }

    free(crontab_content);
    if (pclose(out) == -1) {
        return -1;
    }

    return 0;
}