#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <openssl/rand.h>

int random_bytes(unsigned char *out, size_t len)
{
    if (len != 0 && out == NULL)
        return -1;

    while (len > 0) {
        int n = (len > (size_t)INT_MAX) ? INT_MAX : (int)len;
        if (RAND_bytes(out, n) != 1)
            return -1;
        out += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}