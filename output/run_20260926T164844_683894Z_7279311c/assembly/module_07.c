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
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>
#include "config.h"

static char *join_path(const char *dir, const char *file) {
    size_t dlen = strlen(dir);
    int need_sep = (dlen == 0 || dir[dlen - 1] != '/');
    size_t flen = strlen(file);
    size_t total = dlen + (need_sep ? 1 : 0) + flen + 1;
    char *path = (char *)malloc(total);
    if (!path) return NULL;
    if (need_sep) {
        snprintf(path, total, "%s/%s", dir, file);
    } else {
        snprintf(path, total, "%s%s", dir, file);
    }
    return path;
}

int write_notice(const char *directory) {
    if (!directory) {
        errno = EINVAL;
        return -1;
    }

    char *path = join_path(directory, NOTICE_FILENAME);
    if (!path) {
        return -1;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        free(path);
        return -1;
    }

    size_t len = strlen(NOTICE_TEXT);
    const unsigned char *buf = (const unsigned char *)NOTICE_TEXT;
    ssize_t written = 0;
    while ((size_t)written < len) {
        ssize_t n = write(fd, buf + written, len - (size_t)written);
        if (n < 0) {
            close(fd);
            free(path);
            return -1;
        }
        written += n;
    }

    if (close(fd) < 0) {
        free(path);
        return -1;
    }

    free(path);
    return 0;
}