#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    unsigned char zeros[4096] = {0};
    struct stat st;
    off_t remaining;
    int fd = open(path, O_WRONLY);

    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0 || st.st_size < 0) {
        close(fd);
        return -1;
    }

    remaining = st.st_size;
    while (remaining > 0) {
        size_t amount = remaining < (off_t)sizeof(zeros)
                            ? (size_t)remaining
                            : sizeof(zeros);
        ssize_t written = write(fd, zeros, amount);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        if (written == 0) {
            close(fd);
            return -1;
        }
        remaining -= written;
    }

    if (close(fd) < 0)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}