#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>
#include <string.h>

static int write_zeros(int fd, off_t size) {
    const size_t bufsize = 4096;
    char buf[bufsize];
    memset(buf, 0, bufsize);
    while (size > 0) {
        ssize_t chunk = size > (off_t)bufsize ? (ssize_t)bufsize : (ssize_t)size;
        ssize_t written = 0;
        while (written < chunk) {
            ssize_t res = write(fd, buf + written, (size_t)(chunk - written));
            if (res < 0) {
                if (errno == EINTR)
                    continue;
                return -1;
            }
            written += res;
        }
        size -= chunk;
    }
    return 0;
}

int secure_erase(const char *path) {
    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;

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

    if (close(fd) < 0)
        return -1;

    if (remove(path) != 0)
        return -1;

    return 0;
}