#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
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

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        return -1;
    }

    if (fchmod(fd, S_IRUSR | S_IWUSR) != 0) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }

    p = text;
    remaining = strlen(text);

    while (remaining > 0) {
        ssize_t written = write(fd, p, remaining);

        if (written == -1) {
            if (errno == EINTR) {
                continue;
            }

            int saved_errno = errno;
            (void)close(fd);
            errno = saved_errno;
            return -1;
        }

        if (written == 0) {
            (void)close(fd);
            errno = EIO;
            return -1;
        }

        p += (size_t)written;
        remaining -= (size_t)written;
    }

    if (close(fd) != 0) {
        return -1;
    }

    return 0;
}