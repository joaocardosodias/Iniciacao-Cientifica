#define _GNU_SOURCE
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    size_t required_len = ((data_len + 2) / 3) * 4 + 1; /* include NUL terminator */
    if (out_size < required_len)
        return -1;

    /* EVP_EncodeBlock expects unsigned char* for output */
    EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    return 0;
}