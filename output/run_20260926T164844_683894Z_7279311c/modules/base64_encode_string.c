#define _GNU_SOURCE
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    if (!data || !out)
        return -1;

    size_t required_len = ((data_len + 2) / 3) * 4; /* encoded length without NUL */
    if (out_size < required_len + 1)
        return -1;

    int written = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    if (written < 0)
        return -1;

    /* EVP_EncodeBlock writes a terminating NUL, but ensure it explicitly */
    out[written] = '\0';
    return 0;
}