#include <stddef.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t groups;
    size_t encoded_len;
    size_t i = 0;
    size_t o = 0;
    size_t remainder;

    if (out == NULL || (data == NULL && data_len != 0) || out_size == 0)
        return -1;

    groups = data_len / 3;
    remainder = data_len % 3;

    if (groups > ((size_t)-1 - (remainder != 0 ? 4U : 0U)) / 4)
        return -1;

    encoded_len = groups * 4 + (remainder != 0 ? 4 : 0);
    if (encoded_len >= out_size)
        return -1;

    while (data_len - i >= 3) {
        unsigned int value = ((unsigned int)data[i] << 16) |
                             ((unsigned int)data[i + 1] << 8) |
                             (unsigned int)data[i + 2];

        out[o++] = alphabet[(value >> 18) & 0x3f];
        out[o++] = alphabet[(value >> 12) & 0x3f];
        out[o++] = alphabet[(value >> 6) & 0x3f];
        out[o++] = alphabet[value & 0x3f];
        i += 3;
    }

    if (remainder == 1) {
        unsigned int value = (unsigned int)data[i] << 16;

        out[o++] = alphabet[(value >> 18) & 0x3f];
        out[o++] = alphabet[(value >> 12) & 0x3f];
        out[o++] = '=';
        out[o++] = '=';
    } else if (remainder == 2) {
        unsigned int value = ((unsigned int)data[i] << 16) |
                             ((unsigned int)data[i + 1] << 8);

        out[o++] = alphabet[(value >> 18) & 0x3f];
        out[o++] = alphabet[(value >> 12) & 0x3f];
        out[o++] = alphabet[(value >> 6) & 0x3f];
        out[o++] = '=';
    }

    out[o] = '\0';
    return 0;
}