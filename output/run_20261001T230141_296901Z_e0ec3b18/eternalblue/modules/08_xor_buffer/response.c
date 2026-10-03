#include <stddef.h>
#include <stdint.h>

void xor_buffer(uint8_t *data, size_t len, unsigned int key)
{
    size_t i;
    unsigned int current = key;

    for (i = 0; i < len; ++i) {
        data[i] ^= (uint8_t)current;
        current = (current >> 8) | (current << 24);
    }
}