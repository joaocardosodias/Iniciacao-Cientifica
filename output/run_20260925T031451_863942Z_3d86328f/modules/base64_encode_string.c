#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    unsigned char empty_input = 0;
    size_t encoded_len;
    int result;

    if (out == NULL || (data == NULL && data_len != 0) || data_len > (size_t)INT_MAX)
        return -1;

    encoded_len = ((data_len + 2) / 3) * 4;
    if (encoded_len > (size_t)INT_MAX || out_size <= encoded_len)
        return -1;

    if (data == NULL)
        data = &empty_input;

    result = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    if (result < 0 || (size_t)result != encoded_len)
        return -1;

    out[encoded_len] = '\0';
    return 0;
}