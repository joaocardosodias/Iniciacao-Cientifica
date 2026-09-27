#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    if (directory == NULL) {
        return -1;
    }

    size_t directory_length = strlen(directory);
    const char *separator =
        directory_length > 0 && directory[directory_length - 1] == '/' ? "" : "/";
    char *path = NULL;
    if (asprintf(&path, "%s%s%s", directory, separator, NOTICE_FILENAME) < 0) {
        return -1;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0666);
    free(path);
    if (fd < 0) {
        return -1;
    }

    const char *text = NOTICE_TEXT;
    size_t remaining = strlen(text);
    const char *cursor = text;
    int result = 0;

    while (remaining > 0) {
        ssize_t written = write(fd, cursor, remaining);
        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
            result = -1;
            break;
        }
        if (written == 0) {
            result = -1;
            break;
        }
        cursor += written;
        remaining -= (size_t)written;
    }

    if (close(fd) < 0) {
        result = -1;
    }

    return result;
}