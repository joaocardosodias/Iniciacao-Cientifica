#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <string.h>
#include <errno.h>

int secure_erase(const char *path)
{
    if (path == NULL)
        return -1;

    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;

    struct stat st;
    if (fstat(fd, &st) != 0) {
        close(fd);
        return -1;
    }

    off_t length = st.st_size;

    if (length > 0) {
        if (lseek(fd, 0, SEEK_SET) == (off_t)-1) {
            close(fd);
            return -1;
        }

        static const size_t BUF_SIZE = 65536;
        char *buf = calloc(1, BUF_SIZE);
        if (buf == NULL) {
            close(fd);
            return -1;
        }

        off_t remaining = length;
        while (remaining > 0) {
            size_t to_write = (remaining < (off_t)BUF_SIZE)
                                  ? (size_t)remaining
                                  : BUF_SIZE;
            size_t written = 0;
            while (written < to_write) {
                ssize_t n = write(fd, buf + written, to_write - written);
                if (n < 0) {
                    if (errno == EINTR)
                        continue;
                    free(buf);
                    close(fd);
                    return -1;
                }
                written += (size_t)n;
            }
            remaining -= (off_t)to_write;
        }

        free(buf);

        if (fsync(fd) != 0) {
            close(fd);
            return -1;
        }
    }

    if (close(fd) != 0)
        return -1;

    if (remove(path) != 0)
        return -1;

    return 0;
}