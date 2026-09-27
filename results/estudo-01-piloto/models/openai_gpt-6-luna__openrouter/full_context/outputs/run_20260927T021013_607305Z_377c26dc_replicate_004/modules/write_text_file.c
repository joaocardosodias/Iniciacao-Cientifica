#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int write_text_file(const char *path, const char *text)
{
    int fd;
    int result = 0;
    size_t remaining;
    const char *current;

    if (path == NULL || text == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd == -1)
        return -1;

    current = text;
    remaining = strlen(text);

    while (remaining > 0) {
        ssize_t written = write(fd, current, remaining);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            result = -1;
            break;
        }
        if (written == 0) {
            errno = EIO;
            result = -1;
            break;
        }

        current += written;
        remaining -= (size_t)written;
    }

    if (close(fd) == -1)
        result = -1;

    return result;
}