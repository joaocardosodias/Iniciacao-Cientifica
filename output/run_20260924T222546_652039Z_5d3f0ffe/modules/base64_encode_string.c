#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    size_t needed;

    if (out == NULL)
        return -1;
    if (data == NULL && data_len != 0)
        return -1;
    if (data_len > (size_t)INT_MAX)
        return -1;

    needed = 4 * ((data_len + 2) / 3) + 1;
    if (out_size < needed)
        return -1;

    if (data_len == 0) {
        out[0] = '\0';
        return 0;
    }

    EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    return 0;
}