#define _GNU_SOURCE
#include "config.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    enum {
        NONCE_LEN = 12,
        TAG_LEN = 16,
        CHUNK_SIZE = 65536
    };

    int result = -1;
    int fd = -1;
    int temp_exists = 0;
    FILE *input = NULL;
    FILE *output = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    char *output_path = NULL;
    char *temp_path = NULL;
    unsigned char nonce[NONCE_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char inbuf[CHUNK_SIZE];
    unsigned char outbuf[CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH];

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    size_t path_len = strlen(path);
    size_t suffix_len = strlen(ENCRYPTED_SUFFIX);
    if (suffix_len > SIZE_MAX - path_len - 1)
        return -1;

    size_t output_len = path_len + suffix_len;
    output_path = malloc(output_len + 1);
    if (output_path == NULL)
        goto cleanup;
    memcpy(output_path, path, path_len);
    memcpy(output_path + path_len, ENCRYPTED_SUFFIX, suffix_len + 1);

    if (strcmp(path, output_path) == 0)
        goto cleanup;

    static const char temp_suffix[] = ".tmp.XXXXXX";
    if (output_len > SIZE_MAX - sizeof(temp_suffix))
        goto cleanup;
    temp_path = malloc(output_len + sizeof(temp_suffix));
    if (temp_path == NULL)
        goto cleanup;
    memcpy(temp_path, output_path, output_len);
    memcpy(temp_path + output_len, temp_suffix, sizeof(temp_suffix));

    input = fopen(path, "rb");
    if (input == NULL)
        goto cleanup;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    fd = mkstemp(temp_path);
    if (fd < 0)
        goto cleanup;
    temp_exists = 1;

    output = fdopen(fd, "wb");
    if (output == NULL)
        goto cleanup;
    fd = -1;

    if (fwrite(nonce, 1, sizeof(nonce), output) != sizeof(nonce))
        goto cleanup;

    for (;;) {
        size_t bytes_read = fread(inbuf, 1, sizeof(inbuf), input);
        if (bytes_read > 0) {
            int bytes_written = 0;
            if (EVP_EncryptUpdate(ctx, outbuf, &bytes_written, inbuf,
                                  (int)bytes_read) != 1 ||
                bytes_written < 0 ||
                fwrite(outbuf, 1, (size_t)bytes_written, output) !=
                    (size_t)bytes_written)
                goto cleanup;
        }

        if (bytes_read < sizeof(inbuf)) {
            if (ferror(input))
                goto cleanup;
            if (feof(input))
                break;
        }
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, outbuf, &final_len) != 1 ||
        final_len < 0 ||
        fwrite(outbuf, 1, (size_t)final_len, output) != (size_t)final_len ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1 ||
        fwrite(tag, 1, sizeof(tag), output) != sizeof(tag))
        goto cleanup;

    if (fclose(input) != 0) {
        input = NULL;
        goto cleanup;
    }
    input = NULL;

    if (fflush(output) != 0)
        goto cleanup;
    if (fclose(output) != 0) {
        output = NULL;
        goto cleanup;
    }
    output = NULL;

    if (rename(temp_path, output_path) != 0)
        goto cleanup;

    temp_exists = 0;
    result = 0;

cleanup:
    if (input != NULL)
        fclose(input);
    if (output != NULL)
        fclose(output);
    if (fd >= 0)
        close(fd);
    if (temp_exists)
        unlink(temp_path);
    EVP_CIPHER_CTX_free(ctx);
    free(temp_path);
    free(output_path);
    return result;
}