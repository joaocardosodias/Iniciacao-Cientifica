#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <unistd.h>

int write_notice(const char *directory) {
    if (directory == NULL) {
        return -1;
    }

    size_t dir_len = strlen(directory);
    size_t filename_len = strlen(NOTICE_FILENAME);
    size_t path_len = dir_len + 1 + filename_len; // +1 for '/'
    char *path = malloc(path_len + 1);
    if (path == NULL) {
        return -1;
    }

    memcpy(path, directory, dir_len);
    path[dir_len] = '/';
    memcpy(path + dir_len + 1, NOTICE_FILENAME, filename_len);
    path[path_len] = '\0';

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (fd == -1) {
        free(path);
        return -1;
    }

    const char *text = NOTICE_TEXT;
    size_t text_len = strlen(text);
    ssize_t written = write(fd, text, text_len);
    if (written == -1 || (size_t)written != text_len) {
        close(fd);
        free(path);
        return -1;
    }

    if (close(fd) == -1) {
        free(path);
        return -1;
    }

    free(path);
    return 0;
}