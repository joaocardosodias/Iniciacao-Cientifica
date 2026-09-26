#define _GNU_SOURCE
#include "config.h"

#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    int dirfd = -1;
    int fd = -1;
    int result = -1;
    size_t length;
    size_t offset = 0;
    const char text[] = NOTICE_TEXT;

    if (directory == NULL)
        return -1;

    dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
        return -1;

    fd = openat(dirfd, NOTICE_FILENAME,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (fd < 0)
        goto done;

    length = strlen(text) + 1;
    while (offset < length) {
        ssize_t written = write(fd, text + offset, length - offset);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            goto done;
        }
        if (written == 0)
            goto done;
        offset += (size_t)written;
    }

    if (close(fd) < 0) {
        fd = -1;
        goto done;
    }
    fd = -1;
    result = 0;

done:
    if (fd >= 0)
        close(fd);
    close(dirfd);
    return result;
}