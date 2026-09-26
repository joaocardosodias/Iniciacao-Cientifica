#define _GNU_SOURCE
#include <openssl/rand.h>
#include <stddef.h>

int random_bytes(unsigned char *out, size_t len) {
    if (out == NULL || len == 0) {
        return -1;
    }
    if (RAND_bytes(out, (int)len) != 1) {
        return -1;
    }
    return 0;
}