#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    const char *filename = NOTICE_FILENAME;
    const char *text = NOTICE_TEXT;
    size_t length;
    size_t written = 0;
    int dirfd;
    int fd;
    int result = 0;

    if (directory == NULL || filename == NULL || text == NULL ||
        filename[0] == '\0' || strcmp(filename, ".") == 0 ||
        strcmp(filename, "..") == 0 || strchr(filename, '/') != NULL) {
        return -1;
    }

    dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0) {
        return -1;
    }

    fd = openat(dirfd, filename,
                O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
                0666);
    if (fd < 0) {
        close(dirfd);
        return -1;
    }

    length = strlen(text);
    while (written < length) {
        ssize_t n = write(fd, text + written, length - written);
        if (n < 0) {
            if (errno == EINTR) {
                continue;
            }
            result = -1;
            break;
        }
        if (n == 0) {
            result = -1;
            break;
        }
        written += (size_t)n;
    }

    if (close(fd) < 0) {
        result = -1;
    }
    if (close(dirfd) < 0) {
        result = -1;
    }

    return result;
}