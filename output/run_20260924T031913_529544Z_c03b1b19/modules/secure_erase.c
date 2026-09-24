#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    unsigned char zeros[4096] = {0};
    struct stat st;
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    int result = 0;
    int saved_errno = 0;
    if (fstat(fd, &st) < 0) {
        result = -1;
        saved_errno = errno;
    } else if (st.st_size < 0) {
        result = -1;
        saved_errno = EIO;
    } else {
        off_t remaining = st.st_size;
        while (remaining > 0) {
            size_t count = remaining < (off_t)sizeof(zeros)
                               ? (size_t)remaining
                               : sizeof(zeros);
            ssize_t written = write(fd, zeros, count);
            if (written < 0) {
                if (errno == EINTR)
                    continue;
                result = -1;
                saved_errno = errno;
                break;
            }
            if (written == 0) {
                result = -1;
                saved_errno = EIO;
                break;
            }
            remaining -= (off_t)written;
        }

        if (result == 0 && fsync(fd) < 0) {
            result = -1;
            saved_errno = errno;
        }
    }

    if (close(fd) < 0 && result == 0) {
        result = -1;
        saved_errno = errno;
    }

    if (result < 0) {
        errno = saved_errno;
        return -1;
    }

    return remove(path) == 0 ? 0 : -1;
}