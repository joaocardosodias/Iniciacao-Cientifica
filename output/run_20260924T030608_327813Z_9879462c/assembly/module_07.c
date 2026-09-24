#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    const char *name = NOTICE_FILENAME;
    const char *text = NOTICE_TEXT;
    size_t length;
    int dirfd;
    int fd;
    int saved_errno;

    if (directory == NULL || name == NULL || text == NULL ||
        name[0] == '\0' || strchr(name, '/') != NULL ||
        strcmp(name, ".") == 0 || strcmp(name, "..") == 0) {
        errno = EINVAL;
        return -1;
    }

    dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd == -1)
        return -1;

    fd = openat(dirfd, name,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                0666);
    if (fd == -1) {
        saved_errno = errno;
        close(dirfd);
        errno = saved_errno;
        return -1;
    }

    length = strlen(text) + 1;
    for (size_t written = 0; written < length;) {
        ssize_t n = write(fd, text + written, length - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            saved_errno = errno;
            close(fd);
            close(dirfd);
            errno = saved_errno;
            return -1;
        }
        if (n == 0) {
            saved_errno = EIO;
            close(fd);
            close(dirfd);
            errno = saved_errno;
            return -1;
        }
        written += (size_t)n;
    }

    if (close(fd) == -1) {
        saved_errno = errno;
        close(dirfd);
        errno = saved_errno;
        return -1;
    }

    if (close(dirfd) == -1)
        return -1;

    return 0;
}