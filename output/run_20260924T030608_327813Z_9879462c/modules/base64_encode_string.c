#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    size_t encoded_len;
    int result;
    static const unsigned char empty_data = 0;

    if (out == NULL || (data == NULL && data_len != 0) || data_len > INT_MAX)
        return -1;

    if (data_len > SIZE_MAX - 2)
        return -1;
    encoded_len = 4 * ((data_len + 2) / 3);
    if (encoded_len > INT_MAX || out_size < encoded_len + 1)
        return -1;

    if (data == NULL)
        data = &empty_data;

    result = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    if (result < 0 || (size_t)result != encoded_len)
        return -1;

    out[encoded_len] = '\0';
    return 0;
}