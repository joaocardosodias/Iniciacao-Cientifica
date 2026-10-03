#include <stddef.h>
#include <stdint.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t full_groups;
    size_t remainder;
    size_t encoded_len;
    size_t i;
    size_t o = 0;

    if (out == NULL || (data == NULL && data_len != 0))
        return -1;

    full_groups = data_len / 3;
    remainder = data_len % 3;

    if (full_groups > (SIZE_MAX - (remainder != 0 ? 4u : 0u)) / 4u)
        return -1;

    encoded_len = full_groups * 4u + (remainder != 0 ? 4u : 0u);
    if (out_size <= encoded_len)
        return -1;

    for (i = 0; i < full_groups; ++i) {
        size_t p = i * 3u;
        unsigned int a = data[p];
        unsigned int b = data[p + 1u];
        unsigned int c = data[p + 2u];

        out[o++] = alphabet[a >> 2];
        out[o++] = alphabet[((a & 0x03u) << 4) | (b >> 4)];
        out[o++] = alphabet[((b & 0x0fu) << 2) | (c >> 6)];
        out[o++] = alphabet[c & 0x3fu];
    }

    if (remainder == 1u) {
        unsigned int a = data[full_groups * 3u];

        out[o++] = alphabet[a >> 2];
        out[o++] = alphabet[(a & 0x03u) << 4];
        out[o++] = '=';
        out[o++] = '=';
    } else if (remainder == 2u) {
        size_t p = full_groups * 3u;
        unsigned int a = data[p];
        unsigned int b = data[p + 1u];

        out[o++] = alphabet[a >> 2];
        out[o++] = alphabet[((a & 0x03u) << 4) | (b >> 4)];
        out[o++] = alphabet[(b & 0x0fu) << 2];
        out[o++] = '=';
    }

    out[o] = '\0';
    return 0;
}