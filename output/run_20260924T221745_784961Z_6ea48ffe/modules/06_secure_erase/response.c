#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int secure_erase(const char *path)
{
    struct stat st;
    int fd;
    off_t file_size;
    off_t written;
    ssize_t ret;
    unsigned char buf[4096];
    size_t to_write;

    if (stat(path, &st) != 0)
        return -1;

    file_size = st.st_size;

    fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;

    memset(buf, 0, sizeof(buf));

    written = 0;
    while (written < file_size) {
        to_write = sizeof(buf);
        if ((off_t)to_write > file_size - written)
            to_write = (size_t)(file_size - written);

        ret = write(fd, buf, to_write);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        if (ret == 0) {
            close(fd);
            return -1;
        }
        written += ret;
    }

    if (fsync(fd) != 0) {
        close(fd);
        return -1;
    }

    if (close(fd) != 0)
        return -1;

    if (remove(path) != 0)
        return -1;

    return 0;
}