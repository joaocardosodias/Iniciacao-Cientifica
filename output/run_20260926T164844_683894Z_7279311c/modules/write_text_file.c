#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>

int write_text_file(const char *path, const char *text) {
    if (!path || !text) {
        errno = EINVAL;
        return -1;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) {
        return -1;
    }

    size_t len = strlen(text);
    ssize_t written = 0;
    const char *ptr = text;

    while (len > 0) {
        ssize_t n = write(fd, ptr, len);
        if (n == -1) {
            close(fd);
            return -1;
        }
        written += n;
        ptr += n;
        len -= n;
    }

    if (close(fd) == -1) {
        return -1;
    }

    return 0;
}