#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    int fd;
    struct stat st;
    off_t remaining;
    const char zeros[4096] = {0};

    do {
        fd = open(path, O_WRONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);
    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0 || st.st_size < 0) {
        int saved_errno = errno;
        if (st.st_size < 0 && saved_errno == 0)
            saved_errno = EIO;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    remaining = st.st_size;
    while (remaining > 0) {
        size_t chunk = remaining < (off_t)sizeof(zeros)
                           ? (size_t)remaining
                           : sizeof(zeros);
        ssize_t written = write(fd, zeros, chunk);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            {
                int saved_errno = errno;
                close(fd);
                errno = saved_errno;
                return -1;
            }
        }
        if (written == 0) {
            int saved_errno = EIO;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        remaining -= written;
    }

    if (close(fd) < 0)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}