#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int write_text_file(const char *path, const char *text)
{
    int fd;
    size_t remaining;
    const char *current;

    if (path == NULL || text == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;

    current = text;
    remaining = strlen(text);

    while (remaining > 0) {
        size_t chunk = remaining > 1048576 ? 1048576 : remaining;
        ssize_t written = write(fd, current, chunk);

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

        current += written;
        remaining -= (size_t)written;
    }

    return close(fd) == 0 ? 0 : -1;
}