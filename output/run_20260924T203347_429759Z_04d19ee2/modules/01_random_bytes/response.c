#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <openssl/rand.h>

int random_bytes(unsigned char *out, size_t len)
{
    if (len != 0 && out == NULL)
        return -1;

    while (len != 0) {
        int chunk = len > INT_MAX ? INT_MAX : (int)len;

        if (RAND_bytes(out, chunk) != 1)
            return -1;

        out += chunk;
        len -= (size_t)chunk;
    }

    return 0;
}