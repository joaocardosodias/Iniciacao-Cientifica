#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    size_t blocks;
    size_t encoded_len;
    int result;

    if (out == NULL || (data_len != 0 && data == NULL) || data_len > INT_MAX)
        return -1;

    blocks = data_len / 3 + (data_len % 3 != 0);
    if (blocks > (size_t)INT_MAX / 4)
        return -1;

    encoded_len = blocks * 4;
    if (out_size <= encoded_len)
        return -1;

    if (data_len == 0) {
        out[0] = '\0';
        return 0;
    }

    result = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    if (result < 0 || (size_t)result != encoded_len)
        return -1;

    out[encoded_len] = '\0';
    return 0;
}