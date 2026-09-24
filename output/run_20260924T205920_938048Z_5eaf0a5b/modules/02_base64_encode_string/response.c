#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    static const unsigned char empty = 0;
    size_t encoded_len;
    int result;

    if (out == NULL || (data == NULL && data_len != 0) || data_len > INT_MAX)
        return -1;

    encoded_len = (data_len / 3) * 4 + (data_len % 3 != 0 ? 4 : 0);
    if (encoded_len > INT_MAX || out_size <= encoded_len)
        return -1;

    result = EVP_EncodeBlock((unsigned char *)out,
                             data != NULL ? data : &empty,
                             (int)data_len);
    if (result < 0 || (size_t)result != encoded_len)
        return -1;

    out[encoded_len] = '\0';
    return 0;
}