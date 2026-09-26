#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "config.h"

static int write_all(int fd, const char *buf, size_t len)
{
    size_t total = 0;
    while (total < len) {
        ssize_t written = write(fd, buf + total, len - total);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        total += (size_t)written;
    }
    return 0;
}

int write_notice(const char *directory)
{
    if (!directory)
        return -1;

    char *path = NULL;
    if (asprintf(&path, "%s/%s", directory, NOTICE_FILENAME) == -1)
        return -1;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        free(path);
        return -1;
    }

    size_t text_len = strlen(NOTICE_TEXT);
    int res = write_all(fd, NOTICE_TEXT, text_len);

    int close_ret = close(fd);
    free(path);

    if (res != 0 || close_ret != 0)
        return -1;

    return 0;
}