#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int write_text_file(const char *path, const char *text)
{
    int fd;
    size_t length;
    size_t written = 0;
    int result = 0;

    if (path == NULL || text == NULL)
        return -1;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (fd == -1)
        return -1;

    length = strlen(text);
    while (written < length) {
        ssize_t n = write(fd, text + written, length - written);
        if (n > 0) {
            written += (size_t)n;
        } else if (n == -1 && errno == EINTR) {
            continue;
        } else {
            result = -1;
            break;
        }
    }

    if (close(fd) == -1)
        result = -1;

    return result;
}