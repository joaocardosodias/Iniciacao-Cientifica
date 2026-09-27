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
        buffer += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    unsigned char nonce[12];
    unsigned char header[13];
    unsigned char tag[16];
    unsigned char input_buffer[65536];
    unsigned char output_buffer[65536 + EVP_MAX_BLOCK_LENGTH];
    char *final_path = NULL;
    char *temporary_path = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int input_fd = -1;
    int temporary_fd = -1;
    int temporary_created = 0;
    int result = -1;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    if (asprintf(&final_path, "%s%s", path, ENCRYPTED_SUFFIX) < 0)
        goto cleanup;
    if (asprintf(&temporary_path, "%s.tmp", final_path) < 0)
        goto cleanup;

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
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1)
        goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    temporary_fd = open(temporary_path,
                        O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                        0600);
    if (temporary_fd < 0)
        goto cleanup;
    temporary_created = 1;

    header[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    for (size_t i = 0; i < sizeof(nonce); i++)
        header[i + 1] = nonce[i];
    if (write_all(temporary_fd, header, sizeof(header)) < 0)
        goto cleanup;

    for (;;) {
        ssize_t bytes_read = read(input_fd, input_buffer, sizeof(input_buffer));
        if (bytes_read < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        if (bytes_read == 0)
            break;

        int bytes_out = 0;
        if (EVP_EncryptUpdate(ctx, output_buffer, &bytes_out, input_buffer,
                              (int)bytes_read) != 1)
            goto cleanup;
        if (write_all(temporary_fd, output_buffer, (size_t)bytes_out) < 0)
            goto cleanup;
    }

    int final_bytes = 0;
    if (EVP_EncryptFinal_ex(ctx, output_buffer, &final_bytes) != 1)
        goto cleanup;
    if (write_all(temporary_fd, output_buffer, (size_t)final_bytes) < 0)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
        goto cleanup;
    if (write_all(temporary_fd, tag, sizeof(tag)) < 0)
        goto cleanup;

    if (fsync(temporary_fd) < 0)
        goto cleanup;
    if (close(temporary_fd) < 0) {
        temporary_fd = -1;
        goto cleanup;
    }
    temporary_fd = -1;

    if (close(input_fd) < 0) {
        input_fd = -1;
        goto cleanup;
    }
    input_fd = -1;

    if (rename(temporary_path, final_path) < 0)
        goto cleanup;

    temporary_created = 0;
    result = 0;

cleanup:
    if (temporary_fd >= 0)
        close(temporary_fd);
    if (input_fd >= 0)
        close(input_fd);
    if (temporary_created)
        unlink(temporary_path);
    EVP_CIPHER_CTX_free(ctx);
    free(temporary_path);
    free(final_path);
    return result;
}