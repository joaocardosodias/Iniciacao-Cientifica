#define _GNU_SOURCE
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>

static int overwrite_with_zeros(int fd, off_t length) {
    static const char zero_buf[4096] = {0};
    off_t offset = 0;
    while (offset < length) {
        size_t to_write = (size_t)((length - offset) < (off_t)sizeof(zero_buf) ? (length - offset) : sizeof(zero_buf));
        ssize_t written = write(fd, zero_buf, to_write);
        if (written <= 0) {
            return -1;
        }
        offset += written;
    }
    return 0;
}

int secure_erase(const char *path) {
    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    if (st.st_size > 0) {
        if (overwrite_with_zeros(fd, st.st_size) < 0) {
            close(fd);
            return -1;
        }
    }

    if (close(fd) < 0) {
        return -1;
    }

    if (remove(path) != 0) {
        return -1;
    }

    return 0;
}