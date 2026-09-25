#define _GNU_SOURCE
#include <stddef.h>
#include <limits.h>
#include <openssl/rand.h>

int random_bytes(unsigned char *out, size_t len)
{
    if (out == NULL && len > 0)
        return -1;

    while (len > 0) {
        int chunk = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;

        if (RAND_bytes(out, chunk) != 1)
            return -1;

        out += chunk;
        len -= (size_t)chunk;
    }

    return 0;
}