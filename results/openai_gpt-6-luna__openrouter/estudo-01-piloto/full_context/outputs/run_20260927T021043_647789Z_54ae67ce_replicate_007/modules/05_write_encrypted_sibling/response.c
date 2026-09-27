#define _GNU_SOURCE
#include <errno.h>

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    (void)path;
    (void)key;
    (void)key_len;
    errno = EPERM;
    return -1;
}