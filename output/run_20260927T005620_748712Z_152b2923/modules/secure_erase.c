#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    unsigned char zeros[65536] = {0};
    off_t remaining = st.st_size;

    while (remaining > 0) {
        size_t chunk = remaining > (off_t)sizeof(zeros)
                           ? sizeof(zeros)
                           : (size_t)remaining;
        ssize_t written = write(fd, zeros, chunk);
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