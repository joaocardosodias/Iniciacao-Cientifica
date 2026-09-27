#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
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
        fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    } while (fd == -1 && errno == EINTR);

    if (fd == -1)
        return -1;

    size_t remaining = strlen(text);
    const char *ptr = text;

    while (remaining > 0) {
        ssize_t written = write(fd, ptr, remaining);
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

        ptr += written;
        remaining -= (size_t)written;
    }

    if (close(fd) == -1)
        return -1;

    return 0;
}