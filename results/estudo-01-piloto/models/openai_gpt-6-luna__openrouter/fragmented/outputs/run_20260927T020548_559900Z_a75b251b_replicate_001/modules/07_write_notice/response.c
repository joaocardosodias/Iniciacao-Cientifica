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
    size_t length;
    size_t written = 0;

    if (directory == NULL)
        return -1;

    dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd == -1)
        return -1;

    fd = openat(dirfd, NOTICE_FILENAME,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd == -1) {
        close(dirfd);
        return -1;
    }

    length = strlen(NOTICE_TEXT);
    while (written < length) {
        ssize_t n = write(fd, NOTICE_TEXT + written, length - written);
        if (n > 0) {
            written += (size_t)n;
        } else if (n == -1 && errno == EINTR) {
            continue;
        } else {
            result = -1;
            break;
        }
    }

    if (close(fd) == -1)
        result = -1;
    if (close(dirfd) == -1)
        result = -1;

    return result;
}