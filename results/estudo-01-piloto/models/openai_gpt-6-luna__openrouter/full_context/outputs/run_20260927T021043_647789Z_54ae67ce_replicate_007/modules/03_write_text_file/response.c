#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int write_text_file(const char *path, const char *text)
{
    int fd;
    size_t len;
    size_t written = 0;

    if (path == NULL || text == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd == -1)
        return -1;

    if (fchmod(fd, 0600) == -1) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    len = strlen(text);
    while (written < len) {
        ssize_t n = write(fd, text + written, len - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            {
                int saved_errno = errno;
                close(fd);
                errno = saved_errno;
            }
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

    if (close(fd) == -1)
        return -1;

    return 0;
}