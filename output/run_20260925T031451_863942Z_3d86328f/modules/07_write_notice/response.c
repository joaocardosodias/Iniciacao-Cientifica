#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    const char *filename = NOTICE_FILENAME;
    const char *text = NOTICE_TEXT;
    int dirfd;
    int fd;
    int saved_errno;
    size_t length;
    size_t written = 0;

    if (directory == NULL || filename == NULL || text == NULL ||
        filename[0] == '\0' || strcmp(filename, ".") == 0 ||
        strcmp(filename, "..") == 0 || strchr(filename, '/') != NULL) {
        errno = EINVAL;
        return -1;
    }

    dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd == -1)
        return -1;

    fd = openat(dirfd, filename,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                0666);
    if (fd == -1) {
        saved_errno = errno;
        close(dirfd);
        errno = saved_errno;
        return -1;
    }

    length = strlen(text) + 1;
    while (written < length) {
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
            close(fd);
            close(dirfd);
            errno = EIO;
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