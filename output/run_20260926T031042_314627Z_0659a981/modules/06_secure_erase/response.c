#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdio.h>

int secure_erase(const char *path)
{
    int fd;
    struct stat st;
    char zeros[65536] = {0};
    off_t remaining;

    if (path == NULL)
        return -1;

    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0 || st.st_size < 0) {
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

    if (close(fd) < 0)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}