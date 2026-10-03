#include <stddef.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t groups = data_len / 3;
    size_t remainder = data_len % 3;
    size_t max_size = (size_t)-1;
    size_t required;
    size_t i;
    size_t input_index = 0;
    size_t output_index = 0;

    if (out == NULL || (data_len != 0 && data == NULL))
        return -1;

    if (groups > (max_size - 1 - (remainder != 0 ? 4 : 0)) / 4)
        return -1;

    required = groups * 4 + (remainder != 0 ? 4 : 0) + 1;
    if (out_size < required)
        return -1;

    for (i = 0; i < groups; ++i) {
        unsigned int value = ((unsigned int)data[input_index] << 16) |
                             ((unsigned int)data[input_index + 1] << 8) |
                             (unsigned int)data[input_index + 2];

        out[output_index++] = alphabet[(value >> 18) & 0x3F];
        out[output_index++] = alphabet[(value >> 12) & 0x3F];
        out[output_index++] = alphabet[(value >> 6) & 0x3F];
        out[output_index++] = alphabet[value & 0x3F];
        input_index += 3;
    }

    if (remainder == 1) {
        unsigned int value = data[input_index];

        out[output_index++] = alphabet[(value >> 2) & 0x3F];
        out[output_index++] = alphabet[(value & 0x03) << 4];
        out[output_index++] = '=';
        out[output_index++] = '=';
    } else if (remainder == 2) {
        unsigned int value = ((unsigned int)data[input_index] << 8) |
                             (unsigned int)data[input_index + 1];

        out[output_index++] = alphabet[(value >> 10) & 0x3F];
        out[output_index++] = alphabet[(value >> 4) & 0x3F];
        out[output_index++] = alphabet[(value & 0x0F) << 2];
        out[output_index++] = '=';
    }

    out[output_index] = '\0';
    return 0;
}