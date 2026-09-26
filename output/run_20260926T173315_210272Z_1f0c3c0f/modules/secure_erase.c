#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

static ssize_t full_write(int fd, const void *buf, size_t count) {
    const char *ptr = (const char *)buf;
    size_t left = count;
    while (left > 0) {
        ssize_t written = write(fd, ptr, left);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        left -= (size_t)written;
        ptr += written;
    }
    return (ssize_t)count;
}

int secure_erase(const char *path) {
    if (!path) {
        errno = EINVAL;
        return -1;
    }

    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    off_t size = st.st_size;
    const size_t bufsize = 8192;
    char zero_buf[bufsize] = {0};

    off_t offset = 0;
    while (offset < size) {
        size_t to_write = (size - offset) > (off_t)bufsize ? bufsize : (size_t)(size - offset);
        if (full_write(fd, zero_buf, to_write) < 0) {
            close(fd);
            return -1;
        }
        offset += (off_t)to_write;
    }

    if (close(fd) < 0)
        return -1;

    if (remove(path) != 0)
        return -1;

    return 0;
}