#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    if (directory == NULL)
        return -1;

    int dir_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dir_fd < 0)
        return -1;

    int file_fd = openat(dir_fd, NOTICE_FILENAME,
                         O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (file_fd < 0) {
        close(dir_fd);
        return -1;
    }

    const char *text = NOTICE_TEXT;
    size_t remaining = strlen(text);
    int result = 0;

    while (remaining > 0) {
        ssize_t written = write(file_fd, text, remaining);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            result = -1;
            break;
        }
        if (written == 0) {
            result = -1;
            break;
        }

        text += written;
        remaining -= (size_t)written;
    }

    if (close(file_fd) < 0)
        result = -1;
    if (close(dir_fd) < 0)
        result = -1;

    return result;
}