#define _GNU_SOURCE
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    size_t needed = ((data_len + 2) / 3) * 4 + 1;
    if (out_size < needed)
        return -1;

    int encoded_len = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    if (encoded_len < 0)
        return -1;

    out[encoded_len] = '\0';
    return 0;
}