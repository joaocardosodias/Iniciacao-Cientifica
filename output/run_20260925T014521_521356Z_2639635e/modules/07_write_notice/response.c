#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

static char *join_path(const char *dir, const char *file)
{
    size_t dlen = strlen(dir);
    size_t flen = strlen(file);
    size_t need = dlen + (dlen && dir[dlen - 1] != '/' ? 1 : 0) + flen + 1;
    char *p = (char *)malloc(need);
    if (!p)
        return NULL;
    strcpy(p, dir);
    if (dlen && dir[dlen - 1] != '/')
        p[dlen] = '/';
    strcpy(p + dlen + (dlen && dir[dlen - 1] != '/' ? 1 : 0), file);
    return p;
}

int write_notice(const char *directory)
{
    char *path = join_path(directory, NOTICE_FILENAME);
    if (!path)
        return -1;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd < 0) {
        free(path);
        return -1;
    }

    const char *text = NOTICE_TEXT;
    size_t total = strlen(text);
    size_t written = 0;
    while (written < total) {
        ssize_t n = write(fd, text + written, total - written);
        if (n <= 0) {
            close(fd);
            free(path);
            return -1;
        }
        written += (size_t)n;
    }

    if (close(fd) < 0) {
        free(path);
        return -1;
    }

    free(path);
    return 0;
}