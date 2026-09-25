#define _GNU_SOURCE
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size) {
    size_t required = 4 * ((data_len + 2) / 3) + 1;
    if (out_size < required) {
        return -1;
    }
    int encoded_len = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    if (encoded_len < 0) {
        return -1;
    }
    /* EVP_EncodeBlock always null‑terminates the output */
    return 0;
}