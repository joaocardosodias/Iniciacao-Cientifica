#define _GNU_SOURCE
#include <stddef.h>
#include <openssl/evp.h>

static size_t required_base64_size(size_t data_len) {
    /* Base64 encodes 3 bytes into 4 characters */
    size_t enc_len = ((data_len + 2) / 3) * 4;
    /* plus terminating NUL */
    return enc_len + 1;
}

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size) {
    if (!data || !out) {
        return -1;
    }

    size_t needed = required_base64_size(data_len);
    if (out_size < needed) {
        return -1;
    }

    int encoded_len = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    if (encoded_len < 0) {
        return -1;
    }

    out[encoded_len] = '\0';
    return 0;
}