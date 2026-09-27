#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    int dir_fd;
    int file_fd;
    const char *text = NOTICE_TEXT;
    size_t length = strlen(text);
    size_t written = 0;

    if (directory == NULL)
        return -1;

    do {
        dir_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    } while (dir_fd < 0 && errno == EINTR);
    if (dir_fd < 0)
        return -1;

    do {
        file_fd = openat(dir_fd, NOTICE_FILENAME,
                         O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    } while (file_fd < 0 && errno == EINTR);
    if (file_fd < 0) {
        close(dir_fd);
        return -1;
    }

    while (written < length) {
        ssize_t n = write(file_fd, text + written, length - written);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(file_fd);
            close(dir_fd);
            return -1;
        }
        if (n == 0) {
            close(file_fd);
            close(dir_fd);
            return -1;
        }
        written += (size_t)n;
    }

    if (close(file_fd) < 0) {
        close(dir_fd);
        return -1;
    }
    if (close(dir_fd) < 0)
        return -1;

    return 0;
}