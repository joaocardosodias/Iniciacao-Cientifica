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
#include <limits.h>
#include "config.h"

static int line_matches(const char *line, const char *binary_path) {
    return strstr(line, "@reboot") && strstr(line, binary_path);
}

int schedule_autostart(const char *binary_path) {
    if (!binary_path) {
        return -1;
    }

    FILE *read_fp = popen("crontab -l", "r");
    if (!read_fp) {
        return -1;
    }

    char *content = NULL;
    size_t total_len = 0;
    int already_present = 0;

    char *line = NULL;
    size_t line_cap = 0;
    while (getline(&line, &line_cap, read_fp) != -1) {
        if (!already_present && line_matches(line, binary_path)) {
            already_present = 1;
        }
        size_t line_len = strlen(line);
        char *tmp = realloc(content, total_len + line_len + 1);
        if (!tmp) {
            free(content);
            free(line);
            pclose(read_fp);
            return -1;
        }
        content = tmp;
        memcpy(content + total_len, line, line_len);
        total_len += line_len;
        content[total_len] = '\0';
    }
    free(line);
    if (pclose(read_fp) == -1) {
        free(content);
        return -1;
    }

    if (!already_present) {
        char entry[PATH_MAX + 256];
        int n = snprintf(entry, sizeof(entry), CRON_ENTRY_TEMPLATE, binary_path);
        if (n < 0 || (size_t)n >= sizeof(entry)) {
            free(content);
            return -1;
        }
        char *tmp = realloc(content, total_len + n + 2);
        if (!tmp) {
            free(content);
            return -1;
        }
        content = tmp;
        memcpy(content + total_len, entry, n);
        total_len += n;
        content[total_len++] = '\n';
        content[total_len] = '\0';
    }

    FILE *write_fp = popen("crontab -", "w");
    if (!write_fp) {
        free(content);
        return -1;
    }

    if (content) {
        if (fwrite(content, 1, total_len, write_fp) != total_len) {
            free(content);
            pclose(write_fp);
            return -1;
        }
    }

    int rc = pclose(write_fp);
    free(content);
    if (rc == -1) {
        return -1;
    }

    return 0;
}