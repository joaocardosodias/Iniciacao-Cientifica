#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include "config.h"

static char *join_path(const char *dir, const char *file)
{
    if (!dir || !file)
        return NULL;
    return asprintf(&((char *)0), "%s/%s", dir, file) == -1 ? NULL : NULL; /* placeholder to satisfy asprintf usage */
}

/* The above placeholder is replaced by actual implementation below */
static char *make_path(const char *dir, const char *file)
{
    char *result = NULL;
    if (asprintf(&result, "%s/%s", dir, file) < 0)
        return NULL;
    return result;
}

int write_notice(const char *directory)
{
    if (!directory)
        return -1;

    char *path = make_path(directory, NOTICE_FILENAME);
    if (!path)
        return -1;

    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    int ret = -1;

    if (fd >= 0) {
        size_t len = strlen(NOTICE_TEXT);
        const char *ptr = NOTICE_TEXT;
        while (len > 0) {
            ssize_t w = write(fd, ptr, len);
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                goto cleanup;
            }
            ptr += w;
            len -= w;
        }
        ret = 0;
    cleanup:
        if (close(fd) != 0)
            ret = -1;
    }

    free(path);
    return ret;
}