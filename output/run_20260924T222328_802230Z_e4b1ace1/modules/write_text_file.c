#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>

int write_text_file(const char *path, const char *text)
{
    if (path == NULL || text == NULL)
        return -1;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;

    size_t len = strlen(text);
    size_t off = 0;

    while (off < len) {
        ssize_t n = write(fd, text + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        off += (size_t)n;
    }

    if (close(fd) < 0)
        return -1;

    return 0;
}