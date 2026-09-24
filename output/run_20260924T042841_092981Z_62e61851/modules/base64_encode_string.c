#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    static const unsigned char empty = 0;
    size_t blocks;
    size_t encoded_len;
    int written;

    if (out == NULL || (data == NULL && data_len != 0) || data_len > INT_MAX)
        return -1;

    blocks = data_len / 3 + (data_len % 3 != 0);
    if (blocks > INT_MAX / 4)
        return -1;

    encoded_len = blocks * 4;
    if (out_size <= encoded_len)
        return -1;

    written = EVP_EncodeBlock((unsigned char *)out,
                              data != NULL ? data : &empty,
                              (int)data_len);
    if (written != (int)encoded_len)
        return -1;

    out[encoded_len] = '\0';
    return 0;
}