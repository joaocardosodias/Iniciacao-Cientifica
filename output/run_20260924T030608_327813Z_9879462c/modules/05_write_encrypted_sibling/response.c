#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

static int write_all(int fd, const unsigned char *data, size_t length)
{
    while (length > 0) {
        ssize_t written = write(fd, data, length);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0)
            return -1;
        data += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    static const unsigned char suffix_template[] = ".tmp.XXXXXX";
    const size_t chunk_size = 65536;
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char input_buffer[65536];
    unsigned char output_buffer[65536 + EVP_MAX_BLOCK_LENGTH];
    EVP_CIPHER_CTX *ctx = NULL;
    char *target_path = NULL;
    char *temp_path = NULL;
    size_t path_len, suffix_len, target_len, temp_suffix_len;
    int input_fd = -1;
    int output_fd = -1;
    int result = -1;
    int committed = 0;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    path_len = strlen(path);
    suffix_len = strlen(ENCRYPTED_SUFFIX);
    if (path_len > SIZE_MAX - suffix_len - 1)
        return -1;
    target_len = path_len + suffix_len;

    temp_suffix_len = sizeof(suffix_template) - 1;
    if (target_len > SIZE_MAX - temp_suffix_len - 1)
        return -1;

    target_path = malloc(target_len + 1);
    temp_path = malloc(target_len + temp_suffix_len + 1);
    if (target_path == NULL || temp_path == NULL)
        goto cleanup;

    memcpy(target_path, path, path_len);
    memcpy(target_path + path_len, ENCRYPTED_SUFFIX, suffix_len);
    target_path[target_len] = '\0';
    memcpy(temp_path, target_path, target_len);
    memcpy(temp_path + target_len, suffix_template, temp_suffix_len + 1);

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto cleanup;

    output_fd = mkstemp(temp_path);
    if (output_fd < 0)
        goto cleanup;
    (void)fcntl(output_fd, F_SETFD, FD_CLOEXEC);

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    if (write_all(output_fd, nonce, sizeof(nonce)) < 0)
        goto cleanup;

    for (;;) {
        ssize_t bytes_read = read(input_fd, input_buffer, chunk_size);
        int output_len = 0;

        if (bytes_read < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        if (bytes_read == 0)
            break;

        if (EVP_EncryptUpdate(ctx, output_buffer, &output_len, input_buffer,
                              (int)bytes_read) != 1 ||
            output_len < 0 ||
            (size_t)output_len > sizeof(output_buffer) ||
            write_all(output_fd, output_buffer, (size_t)output_len) < 0)
            goto cleanup;
    }

    {
        int output_len = 0;
        if (EVP_EncryptFinal_ex(ctx, output_buffer, &output_len) != 1 ||
            output_len < 0 ||
            (size_t)output_len > sizeof(output_buffer) ||
            write_all(output_fd, output_buffer, (size_t)output_len) < 0 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1 ||
            write_all(output_fd, tag, sizeof(tag)) < 0)
            goto cleanup;
    }

    if (close(input_fd) < 0) {
        input_fd = -1;
        goto cleanup;
    }
    input_fd = -1;

    if (fsync(output_fd) < 0)
        goto cleanup;
    if (close(output_fd) < 0) {
        output_fd = -1;
        goto cleanup;
    }
    output_fd = -1;

    if (rename(temp_path, target_path) < 0)
        goto cleanup;

    committed = 1;
    result = 0;

cleanup:
    if (input_fd >= 0)
        (void)close(input_fd);
    if (output_fd >= 0)
        (void)close(output_fd);
    if (!committed && temp_path != NULL)
        (void)unlink(temp_path);
    EVP_CIPHER_CTX_free(ctx);
    free(temp_path);
    free(target_path);
    return result;
}