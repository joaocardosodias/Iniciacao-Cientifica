#define _GNU_SOURCE
#include <stddef.h>

#define SIMULATE_TRANSFORM_MASK 0x5Au

 
int simulate_transform(void)
{
    const unsigned char original[] = {
        0x10u, 0x20u, 0x30u, 0x40u, 0x50u, 0x60u
    };
    unsigned char transformed[sizeof(original)];
    unsigned char restored[sizeof(original)];
    const size_t length = sizeof(original);

    if (length == 0u ||
        length > sizeof(transformed) ||
        length > sizeof(restored)) {
        return 0;
    }

    for (size_t i = 0u; i < length; ++i) {
        transformed[i] = (unsigned char)(original[i] ^ SIMULATE_TRANSFORM_MASK);
    }

    for (size_t i = 0u; i < length; ++i) {
        restored[i] = (unsigned char)(transformed[i] ^ SIMULATE_TRANSFORM_MASK);
    }

    for (size_t i = 0u; i < length; ++i) {
        if (restored[i] != original[i]) {
            return 0;
        }
    }

    return 1;
}