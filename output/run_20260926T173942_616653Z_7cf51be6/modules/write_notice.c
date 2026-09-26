#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include "config.h"

static int build_path(const char *dir, const char *file, char *buf, size_t buflen)
{
    size_t dir_len = strlen(dir);
    size_t file_len = strlen(file);
    int need_sep = (dir_len > 0 && dir[dir_len - 1] != '/');
    size_t total = dir_len + (need_sep ? 1 : 0) + file_len + 1; // +1 for NUL

    if (total > buflen)
        return -1;

    memcpy(buf, dir, dir_len);
    if (need_sep) {
        buf[dir_len] = '/';
        memcpy(buf + dir_len + 1, file, file_len + 1);
    } else {
        memcpy(buf + dir_len, file, file_len + 1);
    }
    return 0;
}

int write_notice(const char *directory)
{
    char path[4096];
    int fd = -1;
    ssize_t written, to_write;
    const char *text = NOTICE_TEXT;
    size_t text_len = strlen(text);

    if (build_path(directory, NOTICE_FILENAME, path, sizeof(path)) < 0)
        return -1;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1)
        return -1;

    to_write = (ssize_t)text_len;
    while (to_write > 0) {
        written = write(fd, text + (text_len - to_write), to_write);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        to_write -= written;
    }

    if (close(fd) == -1)
        return -1;

    return 0;
}