#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stdio.h>

static int write_zeros(int fd, off_t size)
{
    const size_t bufsize = 4096;
    static const char zero_buf[4096] = {0};
    off_t remaining = size;

    while (remaining > 0) {
        size_t chunk = (remaining > (off_t)bufsize) ? bufsize : (size_t)remaining;
        ssize_t written = write(fd, zero_buf, chunk);
        if (written < 0) {
            return -1;
        }
        if ((size_t)written != chunk) {
            remaining -= written;
        } else {
            remaining -= chunk;
        }
    }
    return 0;
}

int secure_erase(const char *path)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    if (write_zeros(fd, st.st_size) < 0) {
        close(fd);
        return -1;
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