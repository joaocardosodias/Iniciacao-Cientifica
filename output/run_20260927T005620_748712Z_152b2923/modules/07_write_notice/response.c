#define _GNU_SOURCE
#include "config.h"

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int write_notice(const char *directory)
{
    char *path = NULL;
    FILE *file;
    size_t length = strlen(NOTICE_TEXT);
    int result = 0;

    if (directory == NULL)
        return -1;

    if (asprintf(&path, "%s%s%s", directory,
                 directory[0] != '\0' && directory[strlen(directory) - 1] == '/'
                     ? "" : "/",
                 NOTICE_FILENAME) < 0)
        return -1;

    file = fopen(path, "wb");
    free(path);
    if (file == NULL)
        return -1;

    if (fwrite(NOTICE_TEXT, 1, length, file) != length)
        result = -1;
    if (fclose(file) != 0)
        result = -1;

    return result;
}