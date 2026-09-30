#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd == -1)
        return -1;

    struct stat st;
    if (fstat(fd, &st) == -1 || st.st_size < 0) {
        int saved_errno = errno;
        if (st.st_size < 0)
            saved_errno = EIO;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    char zeros[65536];
    memset(zeros, 0, sizeof(zeros));

    off_t remaining = st.st_size;
    while (remaining > 0) {
        size_t count = remaining < (off_t)sizeof(zeros)
                           ? (size_t)remaining
                           : sizeof(zeros);
        ssize_t written = write(fd, zeros, count);
        if (written == -1) {
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
        remaining -= written;
    }

    if (close(fd) == -1)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}