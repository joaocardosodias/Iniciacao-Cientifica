#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    static const unsigned char zeros[65536] = {0};
    struct stat st;
    off_t remaining;
    int fd = open(path, O_WRONLY);

    if (fd == -1)
        return -1;

    if (fstat(fd, &st) == -1 || st.st_size < 0) {
        (void)close(fd);
        return -1;
    }

    remaining = st.st_size;
    while (remaining > 0) {
        size_t chunk = remaining > (off_t)sizeof(zeros)
                           ? sizeof(zeros)
                           : (size_t)remaining;
        ssize_t written = write(fd, zeros, chunk);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            (void)close(fd);
            return -1;
        }
        if (written == 0) {
            (void)close(fd);
            return -1;
        }
        remaining -= written;
    }

    if (close(fd) == -1)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}