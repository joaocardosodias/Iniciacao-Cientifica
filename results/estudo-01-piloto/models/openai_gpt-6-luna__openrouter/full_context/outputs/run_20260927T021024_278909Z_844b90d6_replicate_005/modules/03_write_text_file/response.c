#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

int write_text_file(const char *path, const char *text)
{
    int fd;
    int saved_errno = 0;
    const char *p;
    size_t remaining;

    if (path == NULL || text == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd == -1)
        return -1;

    p = text;
    remaining = strlen(text);
    while (remaining > 0) {
        size_t chunk = remaining;
        ssize_t written;

        if (chunk > (size_t)SSIZE_MAX)
            chunk = (size_t)SSIZE_MAX;

        written = write(fd, p, chunk);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            saved_errno = errno;
            break;
        }
        if (written == 0) {
            saved_errno = EIO;
            break;
        }

        p += written;
        remaining -= (size_t)written;
    }

    if (close(fd) == -1 && saved_errno == 0)
        saved_errno = errno;

    if (saved_errno != 0) {
        errno = saved_errno;
        return -1;
    }

    return 0;
}