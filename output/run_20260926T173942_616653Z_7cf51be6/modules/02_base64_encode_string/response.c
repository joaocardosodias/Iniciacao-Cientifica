#define _GNU_SOURCE
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    size_t needed = ((data_len + 2) / 3) * 4 + 1;
    if (out_size < needed) {
        return -1;
    }
    int ret = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    if (ret < 0) {
        return -1;
    }
    return 0;
}