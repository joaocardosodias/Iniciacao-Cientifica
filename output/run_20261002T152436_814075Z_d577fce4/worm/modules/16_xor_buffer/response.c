#include <stddef.h>
#include <stdint.h>

void xor_buffer(uint8_t *data, size_t len, unsigned int key)
{
    size_t i;

    if (data == NULL) {
        return;
    }

    for (i = 0; i < len; ++i) {
        data[i] ^= (uint8_t)(key & 0xFFu);
        key = (key >> 8) | (key << 24);
    }
}