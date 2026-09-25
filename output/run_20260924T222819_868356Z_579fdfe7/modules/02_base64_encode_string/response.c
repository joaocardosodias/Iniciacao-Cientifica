#define _GNU_SOURCE
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    if (out == NULL)
        return -1;
    if (data == NULL && data_len > 0)
        return -1;

    size_t encoded_len = 4 * ((data_len + 2) / 3);

    if (out_size < encoded_len + 1)
        return -1;

    if (data_len == 0) {
        out[0] = '\0';
        return 0;
    }

    int n = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    if (n < 0)
        return -1;

    out[n] = '\0';
    return 0;
}