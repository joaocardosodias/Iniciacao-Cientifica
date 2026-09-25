#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    const char contents[] = NOTICE_TEXT;
    int directory_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0)
        return -1;

    int file_fd = openat(directory_fd, NOTICE_FILENAME,
                         O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    if (file_fd < 0) {
        close(directory_fd);
        return -1;
    }

    size_t offset = 0;
    int result = 0;

    while (offset < sizeof(contents)) {
        ssize_t written = write(file_fd, contents + offset,
                                sizeof(contents) - offset);
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
        offset += (size_t)written;
    }

    if (close(file_fd) < 0)
        result = -1;
    if (close(directory_fd) < 0)
        result = -1;

    return result;
}