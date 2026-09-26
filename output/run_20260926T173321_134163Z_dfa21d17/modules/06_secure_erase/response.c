#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

int secure_erase(const char *path) {
    int fd = open(path, O_RDWR);
    if (fd < 0) {
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    off_t remaining = st.st_size;
    const size_t chunk = 4096;
    static const char zeros[4096] = {0};

    while (remaining > 0) {
        size_t to_write = (size_t)(remaining > (off_t)chunk ? chunk : remaining);
        ssize_t written = write(fd, zeros, to_write);
        if (written <= 0) {
            close(fd);
            return -1;
        }
        remaining -= written;
    }

    if (fsync(fd) < 0) {
        close(fd);
        return -1;
    }

    if (close(fd) < 0) {
        return -1;
    }

    if (remove(path) != 0) {
        return -1;
    }

    return 0;
}