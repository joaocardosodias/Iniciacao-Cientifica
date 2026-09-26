#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include "config.h"

static int build_path(const char *dir, const char *file, char **out)
{
    if (!dir || !file || !out)
        return -1;

    size_t dir_len = strlen(dir);
    int need_slash = (dir_len == 0 || dir[dir_len - 1] != '/');
    if (asprintf(out, "%s%s%s", dir, need_slash ? "/" : "", file) < 0)
        return -1;
    return 0;
}

int write_notice(const char *directory)
{
    char *path = NULL;
    if (build_path(directory, NOTICE_FILENAME, &path) != 0)
        return -1;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        free(path);
        return -1;
    }

    const char *text = NOTICE_TEXT;
    size_t len = strlen(text);
    size_t offset = 0;

    while (offset < len) {
        ssize_t n = write(fd, text + offset, len - offset);
        if (n < 0) {
            close(fd);
            unlink(path);
            free(path);
            return -1;
        }
        offset += (size_t)n;
    }

    close(fd);
    free(path);
    return 0;
}