#define _GNU_SOURCE
#include <stddef.h>
#include <limits.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    size_t encoded_len;
    int ret;

    if (out == NULL || out_size == 0) {
        return -1;
    }

    if (data == NULL && data_len != 0) {
        return -1;
    }

    if (data_len > (size_t)INT_MAX) {
        return -1;
    }

    encoded_len = ((data_len + 2) / 3) * 4;

    if (out_size <= encoded_len) {
        return -1;
    }

    if (data_len == 0) {
        out[0] = '\0';
        return 0;
    }

    ret = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    if (ret < 0 || (size_t)ret >= out_size) {
        return -1;
    }

    out[ret] = '\0';
    return 0;
}