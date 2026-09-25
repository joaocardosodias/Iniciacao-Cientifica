#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int write_text_file(const char *path, const char *text)
{
    ssize_t n;
    size_t len;
    const char *p;
    int fd;

    if (!path || !text)
        return -1;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;

    if (fchmod(fd, 0600) < 0)
        goto fail;

    p = text;
    len = strlen(text);
    while (len > 0) {
        n = write(fd, p, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            goto fail;
        }
        if (n == 0) {
            errno = EIO;
            goto fail;
        }
        p += (size_t)n;
        len -= (size_t)n;
    }

    if (close(fd) < 0)
        return -1;
    return 0;

fail:
    {
        int saved = errno;
        close(fd);
        errno = saved;
    }
    return -1;
}