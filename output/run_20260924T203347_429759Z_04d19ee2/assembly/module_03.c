#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

int write_text_file(const char *path, const char *text)
{
    int fd;
    const char *p;
    size_t remaining;

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
        size_t count = remaining > 0x7ffff000UL ? 0x7ffff000UL : remaining;
        ssize_t written = write(fd, p, count);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        if (written == 0) {
            close(fd);
            errno = EIO;
            return -1;
        }

        p += written;
        remaining -= (size_t)written;
    }

    return close(fd) == 0 ? 0 : -1;
}