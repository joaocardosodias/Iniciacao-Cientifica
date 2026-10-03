#include <stddef.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t groups = data_len / 3;
    size_t remainder = data_len % 3;
    size_t extra = remainder ? 4 : 0;
    size_t max_size = (size_t)-1;
    size_t required;
    size_t input_index = 0;
    size_t output_index = 0;

    if (out == NULL || (data_len != 0 && data == NULL))
        return -1;

    if (groups > (max_size - extra - 1) / 4)
        return -1;

    required = groups * 4 + extra + 1;
    if (out_size < required)
        return -1;

    while (data_len - input_index >= 3) {
        unsigned int a = data[input_index++];
        unsigned int b = data[input_index++];
        unsigned int c = data[input_index++];

        out[output_index++] = alphabet[a >> 2];
        out[output_index++] = alphabet[((a & 0x03U) << 4) | (b >> 4)];
        out[output_index++] = alphabet[((b & 0x0FU) << 2) | (c >> 6)];
        out[output_index++] = alphabet[c & 0x3FU];
    }

    if (remainder == 1) {
        unsigned int a = data[input_index];

        out[output_index++] = alphabet[a >> 2];
        out[output_index++] = alphabet[(a & 0x03U) << 4];
        out[output_index++] = '=';
        out[output_index++] = '=';
    } else if (remainder == 2) {
        unsigned int a = data[input_index];
        unsigned int b = data[input_index + 1];

        out[output_index++] = alphabet[a >> 2];
        out[output_index++] = alphabet[((a & 0x03U) << 4) | (b >> 4)];
        out[output_index++] = alphabet[(b & 0x0FU) << 2];
        out[output_index++] = '=';
    }

    out[output_index] = '\0';
    return 0;
}