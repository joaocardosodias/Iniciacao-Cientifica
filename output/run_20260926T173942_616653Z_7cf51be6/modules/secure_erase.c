#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int secure_erase(const char *path)
{
    if (!path)
        return -1;

    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    off_t remaining = st.st_size;
    const size_t chunk = 4096;
    char zero_buf[chunk] = {0};

    while (remaining > 0) {
        size_t to_write = (remaining > (off_t)chunk) ? chunk : (size_t)remaining;
        ssize_t written = write(fd, zero_buf, to_write);
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