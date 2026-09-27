#define _GNU_SOURCE
#include <limits.h>
#include <stdint.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    static const unsigned char empty_input = 0;
    size_t groups;
    size_t encoded_size;
    int encoded_len;

    if (out == NULL || (data == NULL && data_len != 0) || data_len > INT_MAX)
        return -1;

    groups = data_len / 3 + (data_len % 3 != 0);
    if (groups > (SIZE_MAX - 1) / 4)
        return -1;

    encoded_size = groups * 4;
    if (encoded_size > INT_MAX || out_size < encoded_size + 1)
        return -1;

    if (data == NULL)
        data = &empty_input;

    encoded_len = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    if (encoded_len < 0 || (size_t)encoded_len != encoded_size)
        return -1;

    out[encoded_size] = '\0';
    return 0;
}