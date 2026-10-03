#include <stddef.h>
#include <stdint.h>

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

    if (groups > (SIZE_MAX - 1) / 4)
        return -1;

    encoded_len = groups * 4;
    if (remainder != 0) {
        if (encoded_len > SIZE_MAX - 5)
            return -1;
        encoded_len += 4;
    }

    if (out_size < encoded_len + 1)
        return -1;

    while (i + 3 <= data_len) {
        unsigned int a = data[i++];
        unsigned int b = data[i++];
        unsigned int c = data[i++];

        out[j++] = alphabet[a >> 2];
        out[j++] = alphabet[((a & 0x03u) << 4) | (b >> 4)];
        out[j++] = alphabet[((b & 0x0fu) << 2) | (c >> 6)];
        out[j++] = alphabet[c & 0x3fu];
    }

    if (remainder == 1) {
        unsigned int a = data[i];

        out[j++] = alphabet[a >> 2];
        out[j++] = alphabet[(a & 0x03u) << 4];
        out[j++] = '=';
        out[j++] = '=';
    } else if (remainder == 2) {
        unsigned int a = data[i++];
        unsigned int b = data[i];

        out[j++] = alphabet[a >> 2];
        out[j++] = alphabet[((a & 0x03u) << 4) | (b >> 4)];
        out[j++] = alphabet[(b & 0x0fu) << 2];
        out[j++] = '=';
    }

    out[j] = '\0';
    return 0;
}