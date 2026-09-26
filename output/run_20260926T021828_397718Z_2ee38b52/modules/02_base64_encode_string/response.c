#define _GNU_SOURCE
#include <openssl/evp.h>
#include <string.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    int encoded_len;
    if (data_len > INT_MAX || out_size == 0)
        return -1;
    // Calculate expected length: ((data_len + 2) / 3) * 4 + 1 for null terminator
    size_t needed = ((data_len + 2) / 3) * 4 + 1;
    if (out_size < needed)
        return -1;
    encoded_len = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    out[encoded_len] = '\0';
    return 0;
}