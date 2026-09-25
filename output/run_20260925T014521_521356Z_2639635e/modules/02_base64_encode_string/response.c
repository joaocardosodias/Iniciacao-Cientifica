#define _GNU_SOURCE
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    if (!data || !out)
        return -1;

    /* Calculate required output size: 4 * ceil(data_len / 3) + 1 for NUL */
    size_t encoded_len = 4 * ((data_len + 2) / 3);
    if (out_size < encoded_len + 1)
        return -1;

    int ret = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    if (ret < 0 || (size_t)ret != encoded_len)
        return -1;

    out[encoded_len] = '\0';
    return 0;
}