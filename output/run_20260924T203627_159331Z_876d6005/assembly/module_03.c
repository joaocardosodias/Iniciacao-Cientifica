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

    int fd;
    do {
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    } while (fd == -1 && errno == EINTR);

    if (fd == -1)
        return -1;

    size_t remaining = strlen(text);
    const char *p = text;

    while (remaining > 0) {
        size_t count = remaining;
        if (count > (size_t)SSIZE_MAX)
            count = (size_t)SSIZE_MAX;

        ssize_t written = write(fd, p, count);
        if (written > 0) {
            p += written;
            remaining -= (size_t)written;
        } else if (written == -1 && errno == EINTR) {
            continue;
        } else {
            int saved_errno = written == 0 ? EIO : errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
    }

    if (close(fd) == -1)
        return -1;

    return 0;
}