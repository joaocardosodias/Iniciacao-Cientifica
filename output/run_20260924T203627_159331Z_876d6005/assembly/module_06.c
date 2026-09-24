#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    unsigned char zeros[65536] = {0};
    struct stat st;
    off_t offset = 0;
    off_t remaining;
    int fd;

    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd == -1)
        return -1;

    if (fstat(fd, &st) == -1) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    if (!S_ISREG(st.st_mode) || st.st_size < 0) {
        close(fd);
        errno = EINVAL;
        return -1;
    }

    remaining = st.st_size;
    while (remaining > 0) {
        size_t count = remaining > (off_t)sizeof(zeros)
                           ? sizeof(zeros)
                           : (size_t)remaining;
        ssize_t written = pwrite(fd, zeros, count, offset);

        if (written == -1) {
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

        offset += written;
        remaining -= written;
    }

    if (close(fd) == -1)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}
