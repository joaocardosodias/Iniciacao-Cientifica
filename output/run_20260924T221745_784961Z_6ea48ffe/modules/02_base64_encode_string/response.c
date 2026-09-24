#define _GNU_SOURCE
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    /* EVP_EncodeBlock output length: ceil(data_len / 3) * 4, plus NUL */
    size_t required = ((data_len + 2) / 3) * 4 + 1;
    if (out_size < required)
        return -1;

    EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    return 0;
}