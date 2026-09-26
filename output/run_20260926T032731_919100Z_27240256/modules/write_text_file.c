#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>

static ssize_t full_write(int fd, const void *buf, size_t count)
{
    const char *p = (const char *)buf;
    size_t remaining = count;
    while (remaining > 0) {
        ssize_t written = write(fd, p, remaining);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        p += written;
        remaining -= written;
    }
    return (ssize_t)count;
}

int write_text_file(const char *path, const char *text)
{
    if (!path || !text) {
        errno = EINVAL;
        return -1;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;

    size_t len = strlen(text);
    if (full_write(fd, text, len) < 0) {
        int saved_err = errno;
        close(fd);
        errno = saved_err;
        return -1;
    }

    if (close(fd) < 0)
        return -1;

    return 0;
}