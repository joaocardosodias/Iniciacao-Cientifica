#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <openssl/rand.h>

int random_bytes(unsigned char *out, size_t len)
{
    if (len == 0)
        return 0;
    if (out == NULL)
        return -1;

    size_t offset = 0;
    while (offset < len) {
        size_t remaining = len - offset;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        if (RAND_bytes(out + offset, chunk) != 1)
            return -1;
        offset += (size_t)chunk;
    }

    return 0;
}