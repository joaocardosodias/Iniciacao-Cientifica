#include <stddef.h>
#include <stdint.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t groups;
    size_t required;
    size_t i = 0;
    size_t j = 0;

    if (out == NULL || (data_len != 0 && data == NULL))
        return -1;

    groups = data_len / 3 + (data_len % 3 != 0);
    if (groups > (SIZE_MAX - 1) / 4)
        return -1;

    required = groups * 4 + 1;
    if (out_size < required)
        return -1;

    while (data_len - i >= 3) {
        unsigned int value = ((unsigned int)data[i] << 16) |
                             ((unsigned int)data[i + 1] << 8) |
                             (unsigned int)data[i + 2];

        out[j++] = alphabet[(value >> 18) & 0x3F];
        out[j++] = alphabet[(value >> 12) & 0x3F];
        out[j++] = alphabet[(value >> 6) & 0x3F];
        out[j++] = alphabet[value & 0x3F];
        i += 3;
    }

    if (data_len - i == 1) {
        unsigned int value = (unsigned int)data[i] << 16;

        out[j++] = alphabet[(value >> 18) & 0x3F];
        out[j++] = alphabet[(value >> 12) & 0x3F];
        out[j++] = '=';
        out[j++] = '=';
    } else if (data_len - i == 2) {
        unsigned int value = ((unsigned int)data[i] << 16) |
                             ((unsigned int)data[i + 1] << 8);

        out[j++] = alphabet[(value >> 18) & 0x3F];
        out[j++] = alphabet[(value >> 12) & 0x3F];
        out[j++] = alphabet[(value >> 6) & 0x3F];
        out[j++] = '=';
    }

    out[j] = '\0';
    return 0;
}