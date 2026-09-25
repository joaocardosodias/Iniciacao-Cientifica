#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include "config.h"

static ssize_t write_all(int fd, const void *buf, size_t count) {
    const char *ptr = (const char *)buf;
    while (count > 0) {
        ssize_t written = write(fd, ptr, count);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        ptr += written;
        count -= written;
    }
    return 0;
}

int write_notice(const char *directory) {
    if (!directory) {
        errno = EINVAL;
        return -1;
    }

    size_t dir_len = strlen(directory);
    size_t fn_len = strlen(NOTICE_FILENAME);
    size_t path_len = dir_len + 1 + fn_len + 1; /* '/' and NUL */

    char *path = (char *)malloc(path_len);
    if (!path)
        return -1;

    if (dir_len == 0) {
        snprintf(path, path_len, "%s", NOTICE_FILENAME);
    } else {
        snprintf(path, path_len, "%s/%s", directory, NOTICE_FILENAME);
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd < 0) {
        free(path);
        return -1;
    }

    const char *text = NOTICE_TEXT;
    size_t text_len = strlen(text);

    if (write_all(fd, text, text_len) < 0) {
        close(fd);
        free(path);
        return -1;
    }

    if (close(fd) < 0) {
        free(path);
        return -1;
    }

    free(path);
    return 0;
}