#define _GNU_SOURCE
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    if (out == NULL || (data == NULL && data_len != 0))
        return -1;

    size_t encoded_len = ((data_len + 2) / 3) * 4;

    if (out_size < encoded_len + 1)
        return -1;

    int written = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    if (written < 0)
        return -1;

    out[written] = '\0';
    return 0;
}