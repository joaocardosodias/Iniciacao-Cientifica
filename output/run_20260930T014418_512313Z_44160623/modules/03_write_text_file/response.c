#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

int write_text_file(const char *path, const char *text)
{
    if (path == NULL || text == NULL) {
        errno = EINVAL;
        return -1;
    }

    size_t length = strlen(text);
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd == -1)
        return -1;

    size_t written = 0;
    while (written < length) {
        size_t remaining = length - written;
        if (remaining > (size_t)SSIZE_MAX)
            remaining = (size_t)SSIZE_MAX;

        ssize_t result = write(fd, text + written, remaining);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        if (result == 0) {
            int saved_errno = EIO;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        written += (size_t)result;
    }

    if (close(fd) == -1)
        return -1;

    return 0;
}