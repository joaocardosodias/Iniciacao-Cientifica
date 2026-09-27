#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

int write_text_file(const char *path, const char *text)
{
    int fd;
    size_t remaining;
    const char *p;

    if (path == NULL || text == NULL) {
        errno = EINVAL;
        return -1;
    }

    do {
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0)
        return -1;

    p = text;
    remaining = strlen(text);
    while (remaining > 0) {
        size_t chunk = remaining;
        ssize_t written;

        if (chunk > 1048576)
            chunk = 1048576;

        written = write(fd, p, chunk);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        if (written == 0) {
            close(fd);
            errno = EIO;
            return -1;
        }

        p += (size_t)written;
        remaining -= (size_t)written;
    }

    if (close(fd) < 0)
        return -1;

    return 0;
}