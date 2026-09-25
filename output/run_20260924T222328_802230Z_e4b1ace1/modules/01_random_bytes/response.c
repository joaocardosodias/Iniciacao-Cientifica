#define _GNU_SOURCE
#include <stddef.h>
#include <openssl/rand.h>

int random_bytes(unsigned char *out, size_t len)
{
    if (out == NULL && len != 0)
        return -1;

    if (len == 0)
        return 0;

    while (len > 0) {
        size_t chunk = len;
        if (chunk > (size_t)INT_MAX)
            chunk = (size_t)INT_MAX;

        if (RAND_bytes(out, (int)chunk) != 1)
            return -1;

        out += chunk;
        len -= chunk;
    }

    return 0;
}