#define _GNU_SOURCE
#include <stdint.h>
#include <stddef.h>

void xor_buffer(uint8_t *data, size_t len, unsigned int key)
{
    for (size_t i = 0; i < len; ++i) {
        data[i] ^= (uint8_t)key;
        key = (key >> 8) | (key << 24);
    }
}