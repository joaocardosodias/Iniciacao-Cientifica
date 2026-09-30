#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    if (directory == NULL)
        return -1;

    int dirfd = open(directory, O_RDONLY | O_DIRECTORY);
    if (dirfd < 0)
        return -1;

    int fd = openat(dirfd, NOTICE_FILENAME, O_WRONLY | O_CREAT | O_TRUNC, 0666);
    if (fd < 0) {
        close(dirfd);
        return -1;
    }

    const char *text = NOTICE_TEXT;
    size_t remaining = strlen(text);
    int result = 0;

    while (remaining > 0) {
        size_t chunk = remaining > (size_t)SSIZE_MAX ? (size_t)SSIZE_MAX : remaining;
        ssize_t written = write(fd, text, chunk);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            result = -1;
            break;
        }
        if (written == 0) {
            result = -1;
            break;
        }
        text += written;
        remaining -= (size_t)written;
    }

    if (close(fd) < 0)
        result = -1;
    if (close(dirfd) < 0)
        result = -1;

    return result;
}