#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <string.h>

int write_text_file(const char *path, const char *text)
{
    int fd;
    size_t len;
    ssize_t written;
    const char *ptr;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd < 0)
        return -1;

    len = strlen(text);
    ptr = text;

    while (len > 0) {
        written = write(fd, ptr, len);
        if (written < 0) {
            close(fd);
            return -1;
        }
        ptr += written;
        len -= (size_t)written;
    }

    if (close(fd) < 0)
        return -1;

    return 0;
}