#define _GNU_SOURCE
#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int write_notice(const char *directory)
{
    if (directory == NULL)
        return -1;

    size_t dirlen = strlen(directory);
    size_t namelen = strlen(NOTICE_FILENAME);
    int need_slash = (dirlen > 0 && directory[dirlen - 1] != '/');

    char *path = malloc(dirlen + (size_t)need_slash + namelen + 1);
    if (path == NULL)
        return -1;

    char *p = path;
    memcpy(p, directory, dirlen);
    p += dirlen;
    if (need_slash)
        *p++ = '/';
    memcpy(p, NOTICE_FILENAME, namelen);
    p += namelen;
    *p = '\0';

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    free(path);
    if (fd < 0)
        return -1;

    const char *text = NOTICE_TEXT;
    size_t remaining = strlen(text);
    while (remaining > 0) {
        ssize_t n = write(fd, text, remaining);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        text += n;
        remaining -= (size_t)n;
    }

    if (close(fd) != 0)
        return -1;

    return 0;
}