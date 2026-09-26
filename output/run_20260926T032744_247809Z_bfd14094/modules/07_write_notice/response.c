#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <stdio.h>
#include <string.h>
#include <limits.h>
#include "config.h"

static int construct_path(const char *dir, char *buf, size_t bufsize) {
    if (!dir || !buf) return -1;
    size_t dir_len = strlen(dir);
    size_t fn_len = strlen(NOTICE_FILENAME);
    if (dir_len + 1 + fn_len + 1 > bufsize) return -1;
    if (dir_len == 0) return -1;
    memcpy(buf, dir, dir_len);
    if (dir[dir_len - 1] != '/') {
        buf[dir_len] = '/';
        memcpy(buf + dir_len + 1, NOTICE_FILENAME, fn_len + 1);
    } else {
        memcpy(buf + dir_len, NOTICE_FILENAME, fn_len + 1);
    }
    return 0;
}

int write_notice(const char *directory) {
    char path[PATH_MAX];
    if (construct_path(directory, path, sizeof(path)) < 0) {
        return -1;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return -1;
    }

    size_t txt_len = strlen(NOTICE_TEXT) + 1; /* include NUL terminator */
    ssize_t written = 0;
    const char *p = NOTICE_TEXT;
    while (txt_len > 0) {
        ssize_t ret = write(fd, p, txt_len);
        if (ret < 0) {
            close(fd);
            return -1;
        }
        written += ret;
        p += ret;
        txt_len -= ret;
    }

    if (close(fd) < 0) {
        return -1;
    }
    return 0;
}