#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    size_t encoded_len;

    if (out == NULL || (data == NULL && data_len != 0) || data_len > INT_MAX)
        return -1;

    encoded_len = ((data_len + 2) / 3) * 4;
    if (encoded_len > INT_MAX || out_size < encoded_len + 1)
        return -1;

    if (data_len == 0) {
        out[0] = '\0';
        return 0;
    }

    if (EVP_EncodeBlock((unsigned char *)out, data, (int)data_len) != (int)encoded_len)
        return -1;

    out[encoded_len] = '\0';
    return 0;
}