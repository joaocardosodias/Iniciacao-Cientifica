#define _GNU_SOURCE
#include <errno.h>

int write_text_file(const char *path, const char *text)
{
    (void)path;
    (void)text;
    errno = EPERM;
    return -1;
}