#define _GNU_SOURCE
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