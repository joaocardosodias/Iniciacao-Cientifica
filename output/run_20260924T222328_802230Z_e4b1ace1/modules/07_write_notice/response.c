#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int write_notice(const char *directory)
{
    if (directory == NULL)
        return -1;

    size_t dir_len = strlen(directory);
    size_t name_len = strlen(NOTICE_FILENAME);

    int need_sep = (dir_len > 0 && directory[dir_len - 1] != '/');
    size_t path_len = dir_len + (need_sep ? 1 : 0) + name_len + 1;

    char *path = malloc(path_len);
    if (path == NULL)
        return -1;

    memcpy(path, directory, dir_len);
    size_t pos = dir_len;
    if (need_sep)
        path[pos++] = '/';
    memcpy(path + pos, NOTICE_FILENAME, name_len);
    pos += name_len;
    path[pos] = '\0';

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        free(path);
        return -1;
    }

    free(path);

    const char *text = NOTICE_TEXT;
    size_t total = strlen(text);
    size_t written = 0;

    while (written < total) {
        ssize_t n = write(fd, text + written, total - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        written += (size_t)n;
    }

    if (close(fd) != 0)
        return -1;

    return 0;
}