#define _GNU_SOURCE
#include <errno.h>

int secure_erase(const char *path)
{
    (void)path;
    errno = EPERM;
    return -1;
}