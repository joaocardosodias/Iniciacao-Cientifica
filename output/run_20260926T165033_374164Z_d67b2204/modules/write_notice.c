#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    int dirfd;
    int fd;
    int result = 0;
    const char *text = NOTICE_TEXT;
    size_t remaining;

    if (directory == NULL) {
        return -1;
    }

    dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) {
        return -1;
    }

    fd = openat(dirfd, NOTICE_FILENAME,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) {
        close(dirfd);
        return -1;
    }

    remaining = strlen(text);
    while (remaining > 0) {
        ssize_t written = write(fd, text, remaining);

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
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

    if (close(fd) < 0) {
        result = -1;
    }
    if (close(dirfd) < 0) {
        result = -1;
    }

    return result;
}