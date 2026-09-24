#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <sys/types.h>
#include <unistd.h>
#include <string.h>

int write_text_file(const char *path, const char *text)
{
    int fd;
    size_t remaining;
    const char *p;

    if (path == NULL || text == NULL) {
        errno = EINVAL;
        return -1;
    }

    remaining = strlen(text);
    p = text;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd == -1)
        return -1;

    while (remaining > 0) {
        size_t chunk = remaining;
        ssize_t written;

        if (chunk > (size_t)SSIZE_MAX)
            chunk = (size_t)SSIZE_MAX;

        written = write(fd, p, chunk);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            {
                int saved_errno = errno;
                (void)close(fd);
                errno = saved_errno;
                return -1;
            }
        }
        if (written == 0) {
            int saved_errno = EIO;
            (void)close(fd);
            errno = saved_errno;
            return -1;
        }

        p += (size_t)written;
        remaining -= (size_t)written;
    }

    if (close(fd) == -1)
        return -1;

    return 0;
}