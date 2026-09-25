#define _GNU_SOURCE
#include <stddef.h>
#include <openssl/rand.h>

int random_bytes(unsigned char *out, size_t len) {
    if (out == NULL && len != 0) {
        return -1;
    }
    if (len == 0) {
        return 0;
    }
    if (RAND_bytes(out, (int)len) != 1) {
        return -1;
    }
    return 0;
}