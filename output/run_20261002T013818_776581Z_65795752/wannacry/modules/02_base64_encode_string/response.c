#include <stddef.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t groups = data_len / 3;
    size_t remainder = data_len % 3;
    size_t encoded_len;
    size_t i = 0;
    size_t j = 0;

    if (out == NULL || (data == NULL && data_len != 0))
        return -1;

    if (groups > (size_t)-1 / 4)
        return -1;

    encoded_len = groups * 4;
    if (remainder != 0) {
        if (encoded_len > (size_t)-1 - 4)
            return -1;
        encoded_len += 4;
    }

    if (encoded_len == (size_t)-1 || out_size < encoded_len + 1)
        return -1;

    while (i + 3 <= data_len) {
        unsigned int value = ((unsigned int)data[i] << 16) |
                             ((unsigned int)data[i + 1] << 8) |
                             (unsigned int)data[i + 2];

        out[j++] = alphabet[(value >> 18) & 0x3F];
        out[j++] = alphabet[(value >> 12) & 0x3F];
        out[j++] = alphabet[(value >> 6) & 0x3F];
        out[j++] = alphabet[value & 0x3F];
        i += 3;
    }

    if (remainder == 1) {
        unsigned int value = (unsigned int)data[i] << 16;

        out[j++] = alphabet[(value >> 18) & 0x3F];
        out[j++] = alphabet[(value >> 12) & 0x3F];
        out[j++] = '=';
        out[j++] = '=';
    } else if (remainder == 2) {
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