#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int write_text_file(const char *path, const char *text)
{
    if (path == NULL || text == NULL) {
        errno = EINVAL;
        return -1;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd == -1)
        return -1;

    size_t length = strlen(text);
    size_t written = 0;

    while (written < length) {
        ssize_t result = write(fd, text + written, length - written);
        if (result > 0) {
            written += (size_t)result;
        } else if (result == -1 && errno == EINTR) {
            continue;
        } else {
            int saved_errno = result == 0 ? EIO : errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
    }

    if (close(fd) == -1)
        return -1;

    return 0;
}