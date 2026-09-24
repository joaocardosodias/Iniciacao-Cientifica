#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    size_t encoded_len;
    int result;

    if (data_len > INT_MAX || out == NULL || (data == NULL && data_len != 0))
        return -1;

    encoded_len = 4 * ((data_len + 2) / 3);
    if (encoded_len > INT_MAX || out_size <= encoded_len)
        return -1;

    result = EVP_EncodeBlock((unsigned char *)out,
                             data != NULL ? data : (const unsigned char *)"",
                             (int)data_len);
    if (result != (int)encoded_len)
        return -1;

    out[encoded_len] = '\0';
    return 0;
}