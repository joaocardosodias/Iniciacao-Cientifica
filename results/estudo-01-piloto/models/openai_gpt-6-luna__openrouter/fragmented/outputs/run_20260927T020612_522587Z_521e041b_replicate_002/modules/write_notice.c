#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    int dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
        return -1;

    int fd = openat(dirfd, NOTICE_FILENAME,
                    O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0) {
        close(dirfd);
        return -1;
    }

    const char *text = NOTICE_TEXT;
    size_t length = strlen(text);
    size_t written = 0;
    int result = 0;

    while (written < length) {
        ssize_t n = write(fd, text + written, length - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            result = -1;
            break;
        }
        if (n == 0) {
            result = -1;
            break;
        }
        written += (size_t)n;
    }

    if (close(fd) < 0)
        result = -1;
    if (close(dirfd) < 0)
        result = -1;

    return result;
}