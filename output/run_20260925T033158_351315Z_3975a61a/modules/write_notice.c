#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include "config.h"

static ssize_t full_write(int fd, const void *buf, size_t count) {
    const char *ptr = (const char *)buf;
    size_t left = count;
    while (left > 0) {
        ssize_t written = write(fd, ptr, left);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        ptr += written;
        left -= written;
    }
    return (ssize_t)count;
}

int write_notice(const char *directory) {
    if (!directory) {
        errno = EINVAL;
        return -1;
    }

    char *path = NULL;
    if (asprintf(&path, "%s/%s", directory, NOTICE_FILENAME) < 0) {
        return -1;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        free(path);
        return -1;
    }

    size_t txt_len = strlen(NOTICE_TEXT);
    if (full_write(fd, NOTICE_TEXT, txt_len) < 0) {
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