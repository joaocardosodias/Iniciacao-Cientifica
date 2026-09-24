#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

int secure_erase(const char *path)
{
    static const unsigned char zeros[65536] = {0};
    struct stat st;
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
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }

    if (!S_ISREG(st.st_mode) || st.st_size < 0) {
        int saved_errno = EINVAL;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }

    remaining = st.st_size;
    while (remaining > 0) {
        size_t amount = remaining > (off_t)sizeof(zeros)
                            ? sizeof(zeros)
                            : (size_t)remaining;
        ssize_t written = write(fd, zeros, amount);

        if (written == -1) {
            if (errno == EINTR)
                continue;
            {
                int saved_errno = errno;
                (void)close(fd);
                errno = saved_errno;
                return -1;
            }
        }
        if (written == 0) {
            int saved_errno = EIO;
            (void)close(fd);
            errno = saved_errno;
            return -1;
        }
        remaining -= (off_t)written;
    }

    if (close(fd) == -1)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}