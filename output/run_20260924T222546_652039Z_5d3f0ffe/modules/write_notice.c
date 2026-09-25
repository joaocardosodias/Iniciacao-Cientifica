#define _GNU_SOURCE
#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    char *path;
    int fd;
    const char *p;
    size_t len;

    if (directory == NULL || directory[0] == '\0')
        return -1;

    if (asprintf(&path, "%s/%s", directory, NOTICE_FILENAME) < 0)
        return -1;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    free(path);
    if (fd < 0)
        return -1;

    p = NOTICE_TEXT;
    len = strlen(NOTICE_TEXT);
    while (len > 0) {
        ssize_t n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }

    if (close(fd) < 0)
        return -1;
    return 0;
}