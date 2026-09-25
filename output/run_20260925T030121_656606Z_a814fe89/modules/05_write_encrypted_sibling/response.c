#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int write_all(int fd, const unsigned char *buf, size_t len)
{
    size_t offset = 0;

    while (offset < len) {
        ssize_t written = write(fd, buf + offset, len - offset);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0)
            return -1;
        offset += (size_t)written;
    }
    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char input[65536];
    unsigned char output[65536 + EVP_MAX_BLOCK_LENGTH];
    char *output_path = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int input_fd = -1;
    int output_fd = -1;
    int created_output = 0;
    int result = -1;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    size_t path_len = strlen(path);
    size_t suffix_len = strlen(ENCRYPTED_SUFFIX);
    if (suffix_len > SIZE_MAX - path_len - 1)
        return -1;

    output_path = malloc(path_len + suffix_len + 1);
    if (output_path == NULL)
        goto cleanup;
    memcpy(output_path, path, path_len);
    memcpy(output_path + path_len, ENCRYPTED_SUFFIX, suffix_len + 1);

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto cleanup;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto cleanup;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(nonce), NULL) != 1)
        goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    output_fd = open(output_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (output_fd < 0)
        goto cleanup;
    created_output = 1;

    if (write_all(output_fd, nonce, sizeof(nonce)) < 0)
        goto cleanup;

    for (;;) {
        ssize_t bytes_read = read(input_fd, input, sizeof(input));
        if (bytes_read < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        if (bytes_read == 0)
            break;

        int produced = 0;
        if (EVP_EncryptUpdate(ctx, output, &produced, input, (int)bytes_read) != 1)
            goto cleanup;
        if (produced > 0 && write_all(output_fd, output, (size_t)produced) < 0)
            goto cleanup;
    }

    int produced = 0;
    if (EVP_EncryptFinal_ex(ctx, output, &produced) != 1)
        goto cleanup;
    if (produced > 0 && write_all(output_fd, output, (size_t)produced) < 0)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)sizeof(tag), tag) != 1)
        goto cleanup;
    if (write_all(output_fd, tag, sizeof(tag)) < 0)
        goto cleanup;
    if (fsync(output_fd) < 0)
        goto cleanup;

    {
        int fd = input_fd;
        input_fd = -1;
        if (close(fd) < 0)
            goto cleanup;
    }
    {
        int fd = output_fd;
        output_fd = -1;
        if (close(fd) < 0)
            goto cleanup;
    }

    result = 0;

cleanup:
    if (input_fd >= 0)
        close(input_fd);
    if (output_fd >= 0)
        close(output_fd);
    if (result != 0 && created_output)
        unlink(output_path);
    EVP_CIPHER_CTX_free(ctx);
    free(output_path);
    return result;
}