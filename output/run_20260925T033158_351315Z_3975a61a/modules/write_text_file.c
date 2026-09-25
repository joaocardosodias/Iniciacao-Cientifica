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
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;
    size_t len = strlen(text);
    size_t written_total = 0;
    while (written_total < len) {
        ssize_t n = write(fd, text + written_total, len - written_total);
        if (n < 0) {
            close(fd);
            return -1;
        }
        written_total += (size_t)n;
    }
    if (close(fd) < 0)
        return -1;
    return 0;
}