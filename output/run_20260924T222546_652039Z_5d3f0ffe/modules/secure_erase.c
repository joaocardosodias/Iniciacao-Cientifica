#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    int fd;
    struct stat st;
    off_t remaining;
    char buf[4096];

    if (path == NULL)
        return -1;

    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }

    memset(buf, 0, sizeof(buf));
    remaining = st.st_size;
    while (remaining > 0) {
        size_t chunk;
        ssize_t n;

        chunk = remaining > (off_t)sizeof(buf) ? sizeof(buf) : (size_t)remaining;
        do {
            n = write(fd, buf, chunk);
        } while (n < 0 && errno == EINTR);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        remaining -= n;
    }

    if (fsync(fd) < 0) {
        close(fd);
        return -1;
    }

    if (close(fd) < 0)
        return -1;

    if (remove(path) != 0)
        return -1;

    return 0;
}