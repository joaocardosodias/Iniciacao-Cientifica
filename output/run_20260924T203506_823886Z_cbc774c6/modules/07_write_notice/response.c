#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    const char *text = NOTICE_TEXT;
    size_t remaining = strlen(text);
    int dirfd;
    int fd;
    int saved_errno = 0;

    if (directory == NULL) {
        errno = EINVAL;
        return -1;
    }

    dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd == -1)
        return -1;

    fd = openat(dirfd, NOTICE_FILENAME,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    if (fd == -1) {
        saved_errno = errno;
        close(dirfd);
        errno = saved_errno;
        return -1;
    }

    while (remaining > 0) {
        ssize_t written = write(fd, text, remaining);

        if (written == -1) {
            if (errno == EINTR)
                continue;
            saved_errno = errno;
            break;
        }
        if (written == 0) {
            saved_errno = EIO;
            break;
        }

        text += written;
        remaining -= (size_t)written;
    }

    if (close(fd) == -1 && saved_errno == 0)
        saved_errno = errno;
    if (close(dirfd) == -1 && saved_errno == 0)
        saved_errno = errno;

    if (saved_errno != 0) {
        errno = saved_errno;
        return -1;
    }

    return 0;
}