#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    int dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd == -1)
        return -1;

    int fd = openat(dirfd, NOTICE_FILENAME,
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                    0644);
    if (fd == -1) {
        int saved_errno = errno;
        close(dirfd);
        errno = saved_errno;
        return -1;
    }

    const unsigned char *text = (const unsigned char *)NOTICE_TEXT;
    size_t remaining = strlen(NOTICE_TEXT) + 1;
    int result = 0;

    while (remaining > 0) {
        ssize_t written = write(fd, text, remaining);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            result = -1;
            break;
        }
        if (written == 0) {
            errno = EIO;
            result = -1;
            break;
        }
        text += written;
        remaining -= (size_t)written;
    }

    int saved_errno = errno;
    if (close(fd) == -1 && result == 0) {
        result = -1;
        saved_errno = errno;
    }
    if (close(dirfd) == -1 && result == 0) {
        result = -1;
        saved_errno = errno;
    }
    if (result == -1)
        errno = saved_errno;

    return result;
}