#define _GNU_SOURCE
#include <stddef.h>

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    (void)path;
    (void)key;
    (void)key_len;
    return -1;
}