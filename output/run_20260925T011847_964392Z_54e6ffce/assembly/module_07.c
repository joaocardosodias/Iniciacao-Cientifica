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
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <stdlib.h>
#include <errno.h>
#include "config.h"

static char *build_path(const char *directory, const char *filename) {
    size_t dir_len = strlen(directory);
    size_t file_len = strlen(filename);
    size_t total = dir_len + 1 + file_len + 1;  
    char *path = malloc(total);
    if (!path) {
        return NULL;
    }
    memcpy(path, directory, dir_len);
    path[dir_len] = '/';
    memcpy(path + dir_len + 1, filename, file_len);
    path[dir_len + 1 + file_len] = '\0';
    return path;
}

int write_notice(const char *directory) {
    if (!directory) {
        errno = EINVAL;
        return -1;
    }

    char *path = build_path(directory, NOTICE_FILENAME);
    if (!path) {
        return -1;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    free(path);
    if (fd == -1) {
        return -1;
    }

    const char *text = NOTICE_TEXT;
    size_t len = strlen(text);
    ssize_t written = 0;
    const char *ptr = text;

    while (len > 0) {
        ssize_t r = write(fd, ptr, len);
        if (r == -1) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        written += r;
        ptr += r;
        len -= r;
    }

    if (close(fd) == -1) {
        return -1;
    }

    return 0;
}