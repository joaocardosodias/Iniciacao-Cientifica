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
    const char *cursor;

    if (path == NULL || text == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd == -1)
        return -1;

    cursor = text;
    remaining = strlen(text);

    while (remaining > 0) {
        size_t count = remaining < 1048576 ? remaining : 1048576;
        ssize_t written = write(fd, cursor, count);

        if (written == -1) {
            int saved_errno = errno;

            if (saved_errno == EINTR)
                continue;
            close(fd);
            errno = saved_errno;
            return -1;
        }

        if (written == 0) {
            close(fd);
            errno = EIO;
            return -1;
        }

        cursor += written;
        remaining -= (size_t)written;
    }

    return close(fd) == 0 ? 0 : -1;
}