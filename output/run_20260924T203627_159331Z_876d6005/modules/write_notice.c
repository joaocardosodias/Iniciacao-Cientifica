#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    const char contents[] = NOTICE_TEXT;
    size_t remaining = sizeof(contents);
    const char *position = contents;
    int dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd == -1)
        return -1;

    int fd = openat(dirfd, NOTICE_FILENAME,
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd == -1) {
        int saved_errno = errno;
        close(dirfd);
        errno = saved_errno;
        return -1;
    }

    while (remaining > 0) {
        ssize_t written = write(fd, position, remaining);
        if (written == -1) {
            if (errno == EINTR)
                continue;
            int saved_errno = errno;
            close(fd);
            close(dirfd);
            errno = saved_errno;
            return -1;
        }
        if (written == 0) {
            int saved_errno = EIO;
            close(fd);
            close(dirfd);
            errno = saved_errno;
            return -1;
        }
        position += (size_t)written;
        remaining -= (size_t)written;
    }

    if (close(fd) == -1) {
        int saved_errno = errno;
        close(dirfd);
        errno = saved_errno;
        return -1;
    }

    if (close(dirfd) == -1)
        return -1;

    return 0;
}