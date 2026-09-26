#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <string.h>
#include <unistd.h>

int write_text_file(const char *path, const char *text)
{
    if (path == NULL || text == NULL) {
        errno = EINVAL;
        return -1;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;

    size_t length = strlen(text);
    size_t written = 0;

    while (written < length) {
        ssize_t n = write(fd, text + written, length - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        if (n == 0) {
            int saved_errno = EIO;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        written += (size_t)n;
    }

    if (close(fd) < 0)
        return -1;

    return 0;
}