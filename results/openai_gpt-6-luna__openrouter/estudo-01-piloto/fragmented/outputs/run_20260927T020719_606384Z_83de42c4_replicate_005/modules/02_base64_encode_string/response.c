#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    static const unsigned char empty_input = 0;
    size_t groups;
    size_t encoded_len;
    int result;

    if (out == NULL || (data == NULL && data_len != 0) || data_len > (size_t)INT_MAX)
        return -1;

    groups = data_len / 3 + (data_len % 3 != 0);
    if (groups > (size_t)INT_MAX / 4)
        return -1;

    encoded_len = groups * 4;
    if (out_size <= encoded_len)
        return -1;

    result = EVP_EncodeBlock((unsigned char *)out,
                             data != NULL ? data : &empty_input,
                             (int)data_len);
    if (result < 0 || (size_t)result != encoded_len)
        return -1;

    return 0;
}