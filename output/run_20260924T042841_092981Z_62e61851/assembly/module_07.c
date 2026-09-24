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
    int failed = 0;
    const char *text = NOTICE_TEXT;
    size_t remaining = strlen(text);

    if (directory == NULL) {
        errno = EINVAL;
        return -1;
    }

    dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
        return -1;

    fd = openat(dirfd, NOTICE_FILENAME,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) {
        int saved_errno = errno;
        close(dirfd);
        errno = saved_errno;
        return -1;
    }

    while (remaining > 0) {
        ssize_t written = write(fd, text, remaining);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            failed = 1;
            break;
        }
        if (written == 0) {
            errno = EIO;
            failed = 1;
            break;
        }

        text += written;
        remaining -= (size_t)written;
    }

    if (failed) {
        int saved_errno = errno;
        close(fd);
        close(dirfd);
        errno = saved_errno;
        return -1;
    }

    if (close(fd) < 0) {
        int saved_errno = errno;
        close(dirfd);
        errno = saved_errno;
        return -1;
    }

    if (close(dirfd) < 0)
        return -1;

    return 0;
}