#define _GNU_SOURCE
#include <limits.h>
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    size_t encoded_len;
    size_t groups;
    size_t remainder;
    int result;

    if (out == NULL || (data_len != 0 && data == NULL))
        return -1;

    groups = data_len / 3;
    remainder = data_len % 3;
    if (groups > (size_t)INT_MAX / 4)
        return -1;

    encoded_len = groups * 4;
    if (remainder != 0) {
        if (encoded_len > (size_t)INT_MAX - 4)
            return -1;
        encoded_len += 4;
    }

    if (out_size < encoded_len + 1)
        return -1;

    if (data_len == 0) {
        out[0] = '\0';
        return 0;
    }

    result = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    if (result < 0 || (size_t)result != encoded_len)
        return -1;

    out[encoded_len] = '\0';
    return 0;
}