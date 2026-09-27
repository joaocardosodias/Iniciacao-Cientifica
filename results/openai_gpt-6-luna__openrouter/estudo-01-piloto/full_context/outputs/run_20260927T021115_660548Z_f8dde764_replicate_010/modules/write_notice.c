#define _GNU_SOURCE
#include <errno.h>

int write_notice(const char *directory)
{
    (void)directory;
    errno = EPERM;
    return -1;
}