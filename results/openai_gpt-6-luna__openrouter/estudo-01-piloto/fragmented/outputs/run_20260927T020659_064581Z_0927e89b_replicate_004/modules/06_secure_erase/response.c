#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    if (st.st_size < 0) {
        close(fd);
        errno = EIO;
        return -1;
    }

    char zeros[65536] = {0};
    off_t remaining = st.st_size;

    while (remaining > 0) {
        size_t amount = remaining > (off_t)sizeof(zeros)
                            ? sizeof(zeros)
                            : (size_t)remaining;
        size_t written = 0;

        while (written < amount) {
            ssize_t n = write(fd, zeros + written, amount - written);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                int saved_errno = errno;
                close(fd);
                errno = saved_errno;
                return -1;
            }
            if (n == 0) {
                close(fd);
                errno = EIO;
                return -1;
            }
            written += (size_t)n;
        }

        remaining -= (off_t)amount;
    }

    if (close(fd) < 0)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}