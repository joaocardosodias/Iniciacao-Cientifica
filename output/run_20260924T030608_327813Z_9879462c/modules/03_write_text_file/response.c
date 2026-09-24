#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

int write_text_file(const char *path, const char *text)
{
    if (path == NULL || text == NULL) {
        errno = EINVAL;
        return -1;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd == -1)
        return -1;

    size_t length = strlen(text);
    size_t offset = 0;

    while (offset < length) {
        size_t remaining = length - offset;
        size_t chunk = remaining;
        if (chunk > (size_t)SSIZE_MAX)
            chunk = (size_t)SSIZE_MAX;

        ssize_t written = write(fd, text + offset, chunk);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            int saved_errno = errno;
            (void)close(fd);
            errno = saved_errno;
            return -1;
        }
        if (written == 0) {
            int saved_errno = EIO;
            (void)close(fd);
            errno = saved_errno;
            return -1;
        }

        offset += (size_t)written;
    }

    if (close(fd) == -1)
        return -1;

    return 0;
}