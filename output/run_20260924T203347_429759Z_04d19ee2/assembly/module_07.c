#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    const char *text = NOTICE_TEXT;
    size_t remaining;
    int directory_fd;
    int file_fd;
    int saved_errno;

    if (directory == NULL) {
        errno = EINVAL;
        return -1;
    }

    do {
        directory_fd = open(directory, O_PATH | O_DIRECTORY | O_CLOEXEC);
    } while (directory_fd == -1 && errno == EINTR);

    if (directory_fd == -1)
        return -1;

    do {
        file_fd = openat(directory_fd, NOTICE_FILENAME,
                         O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0644);
    } while (file_fd == -1 && errno == EINTR);

    if (file_fd == -1)
        goto fail_directory;

    remaining = strlen(text);
    while (remaining != 0) {
        ssize_t written = write(file_fd, text, remaining);

        if (written == -1) {
            if (errno == EINTR)
                continue;
            goto fail_file;
        }
        if (written == 0) {
            errno = EIO;
            goto fail_file;
        }

        text += written;
        remaining -= (size_t)written;
    }

    if (close(file_fd) == -1)
        goto fail_directory;

    if (close(directory_fd) == -1)
        return -1;

    return 0;

fail_file:
    saved_errno = errno;
    close(file_fd);
    errno = saved_errno;

fail_directory:
    saved_errno = errno;
    close(directory_fd);
    errno = saved_errno;
    return -1;
}