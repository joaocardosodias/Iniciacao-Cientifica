#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int write_all(int fd, const unsigned char *buffer, size_t length)
{
    while (length > 0) {
        ssize_t written = write(fd, buffer, length);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0)
            return -1;
        buffer += written;
        length -= (size_t)written;
    }
    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    int input_fd = -1;
    int output_fd = -1;
    int result = -1;
    int committed = 0;
    char *output_path = NULL;
    char *temporary_path = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char input_buffer[65536];
    unsigned char output_buffer[65536 + EVP_MAX_BLOCK_LENGTH];

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    if (asprintf(&output_path, "%s%s", path, ENCRYPTED_SUFFIX) < 0)
        goto done;
    if (asprintf(&temporary_path, "%s.XXXXXX", output_path) < 0)
        goto done;

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto done;

    output_fd = mkostemp(temporary_path, O_CLOEXEC);
    if (output_fd < 0)
        goto done;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto done;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto done;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1)
        goto done;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto done;
    if (write_all(output_fd, nonce, sizeof(nonce)) < 0)
        goto done;

    for (;;) {
        ssize_t bytes_read = read(input_fd, input_buffer, sizeof(input_buffer));
        if (bytes_read < 0) {
            if (errno == EINTR)
                continue;
            goto done;
        }
        if (bytes_read == 0)
            break;

        int bytes_out = 0;
        if (EVP_EncryptUpdate(ctx, output_buffer, &bytes_out, input_buffer,
                              (int)bytes_read) != 1)
            goto done;
        if (write_all(output_fd, output_buffer, (size_t)bytes_out) < 0)
            goto done;
    }

    int final_bytes = 0;
    if (EVP_EncryptFinal_ex(ctx, output_buffer, &final_bytes) != 1)
        goto done;
    if (write_all(output_fd, output_buffer, (size_t)final_bytes) < 0)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
        goto done;
    if (write_all(output_fd, tag, sizeof(tag)) < 0)
        goto done;

    if (close(input_fd) < 0) {
        input_fd = -1;
        goto done;
    }
    input_fd = -1;

    if (close(output_fd) < 0) {
        output_fd = -1;
        goto done;
    }
    output_fd = -1;

    if (rename(temporary_path, output_path) < 0)
        goto done;

    committed = 1;
    result = 0;

done:
    if (input_fd >= 0)
        close(input_fd);
    if (output_fd >= 0)
        close(output_fd);
    if (temporary_path != NULL && !committed)
        unlink(temporary_path);
    EVP_CIPHER_CTX_free(ctx);
    free(temporary_path);
    free(output_path);
    return result;
}