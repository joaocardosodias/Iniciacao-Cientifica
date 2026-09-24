#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <string.h>
#include <errno.h>
#include <sys/types.h>
#include <sys/stat.h>

int write_text_file(const char *path, const char *text)
{
    int fd;
    size_t len;
    size_t off = 0;

    if (path == NULL || text == NULL)
        return -1;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;

    if (fchmod(fd, 0600) != 0) {
        close(fd);
        return -1;
    }

    len = strlen(text);
    while (off < len) {
        ssize_t n = write(fd, text + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        if (n == 0) {
            close(fd);
            return -1;
        }
        off += (size_t)n;
    }

    if (fsync(fd) != 0 && errno != EINVAL && errno != EROFS) {
        close(fd);
        return -1;
    }

    if (close(fd) != 0)
        return -1;

    return 0;
}