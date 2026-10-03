#include <stddef.h>
#include <stdint.h>

void xor_buffer(uint8_t *data, size_t len, unsigned int key)
{
    uint32_t rotating_key = (uint32_t)key;

    for (size_t i = 0; i < len; ++i) {
        data[i] ^= (uint8_t)rotating_key;
        rotating_key = (rotating_key >> 8) | (rotating_key << 24);
    }
}