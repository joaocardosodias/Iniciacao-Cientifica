#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>
#include <errno.h>

int write_notice(const char *directory)
{
    char path[4096];
    int n = snprintf(path, sizeof(path), "%s/%s", directory, NOTICE_FILENAME);
    if (n < 0 || (size_t)n >= sizeof(path)) {
        return -1;
    }

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        return -1;
    }

    const char *text = NOTICE_TEXT;
    size_t len = strlen(text);
    size_t written = 0;

    while (written < len) {
        ssize_t ret = write(fd, text + written, len - written);
        if (ret < 0) {
            if (errno == EINTR) {
                continue;
            }
            close(fd);
            return -1;
        }
        written += (size_t)ret;
    }

    if (close(fd) < 0) {
        return -1;
    }

    return 0;
}