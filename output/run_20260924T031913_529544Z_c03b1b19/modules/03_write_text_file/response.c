#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
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

    size_t remaining = strlen(text);
    const char *p = text;

    while (remaining > 0) {
        size_t chunk = remaining;
        if (chunk > (size_t)SSIZE_MAX)
            chunk = (size_t)SSIZE_MAX;

        ssize_t written = write(fd, p, chunk);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        if (written == 0) {
            int saved_errno = EIO;
            close(fd);
            errno = saved_errno;
            return -1;
        }

        p += written;
        remaining -= (size_t)written;
    }

    return close(fd) == 0 ? 0 : -1;
}