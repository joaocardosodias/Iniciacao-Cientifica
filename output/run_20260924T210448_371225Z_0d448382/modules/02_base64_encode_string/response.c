#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    const unsigned char empty = 0;
    size_t groups;
    size_t encoded_len;
    int result;

    if (out == NULL || (data == NULL && data_len != 0) || data_len > INT_MAX)
        return -1;

    groups = data_len / 3 + (data_len % 3 != 0);
    if (groups > INT_MAX / 4)
        return -1;

    encoded_len = groups * 4;
    if (out_size <= encoded_len)
        return -1;

    if (data == NULL)
        data = &empty;

    result = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    return result == (int)encoded_len ? 0 : -1;
}