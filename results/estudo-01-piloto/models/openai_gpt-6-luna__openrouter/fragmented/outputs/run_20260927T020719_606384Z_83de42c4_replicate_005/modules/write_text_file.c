#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <unistd.h>

int write_text_file(const char *path, const char *text)
{
    int fd;
    size_t length;
    size_t offset = 0;

    if (path == NULL || text == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1)
        return -1;

    length = strlen(text);
    while (offset < length) {
        size_t remaining = length - offset;
        size_t chunk = remaining > (size_t)SSIZE_MAX
                           ? (size_t)SSIZE_MAX
                           : remaining;
        ssize_t written = write(fd, text + offset, chunk);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            {
                int saved_errno = errno;
                close(fd);
                errno = saved_errno;
            }
            return -1;
        }
        if (written == 0) {
            int saved_errno = EIO;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        offset += (size_t)written;
    }

    if (close(fd) == -1)
        return -1;

    return 0;
}