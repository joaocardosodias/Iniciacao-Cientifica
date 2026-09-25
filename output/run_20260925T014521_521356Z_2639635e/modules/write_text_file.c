#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>

int write_text_file(const char *path, const char *text) {
    if (!path || !text) {
        return -1;
    }
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1) {
        return -1;
    }
    size_t remaining = strlen(text);
    const char *ptr = text;
    while (remaining > 0) {
        ssize_t written = write(fd, ptr, remaining);
        if (written <= 0) {
            close(fd);
            return -1;
        }
        ptr += written;
        remaining -= written;
    }
    if (close(fd) == -1) {
        return -1;
    }
    return 0;
}