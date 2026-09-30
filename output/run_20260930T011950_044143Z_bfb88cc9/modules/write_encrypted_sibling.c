#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>

static int
write_all(int fd, const unsigned char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        buf += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

int
write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    int input_fd = -1;
    int output_fd = -1;
    int temp_created = 0;
    int result = -1;
    char *final_path = NULL;
    char *temp_path = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char nonce[12];
    unsigned char header[13];
    unsigned char tag[16];
    unsigned char input_buffer[65536];
    unsigned char output_buffer[65536 + EVP_MAX_BLOCK_LENGTH];

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    if (asprintf(&final_path, "%s%s", path, ENCRYPTED_SUFFIX) < 0)
        goto done;
    if (asprintf(&temp_path, "%s.tmp", final_path) < 0)
        goto done;

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto done;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto done;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto done;

    output_fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (output_fd < 0)
        goto done;
    temp_created = 1;

    header[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    for (size_t i = 0; i < sizeof(nonce); ++i)
        header[i + 1] = nonce[i];
    if (write_all(output_fd, header, sizeof(header)) < 0)
        goto done;

    for (;;) {
        ssize_t n = read(input_fd, input_buffer, sizeof(input_buffer));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            goto done;
        }
        if (n == 0)
            break;

        int output_len = 0;
        if (EVP_EncryptUpdate(ctx, output_buffer, &output_len,
                              input_buffer, (int)n) != 1)
            goto done;
        if (output_len > 0 &&
            write_all(output_fd, output_buffer, (size_t)output_len) < 0)
            goto done;
    }

    {
        int output_len = 0;
        if (EVP_EncryptFinal_ex(ctx, output_buffer, &output_len) != 1)
            goto done;
        if (output_len > 0 &&
            write_all(output_fd, output_buffer, (size_t)output_len) < 0)
            goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1 ||
        write_all(output_fd, tag, sizeof(tag)) < 0)
        goto done;

    while (fsync(output_fd) < 0) {
        if (errno != EINTR)
            goto done;
    }

    if (close(output_fd) < 0) {
        output_fd = -1;
        goto done;
    }
    output_fd = -1;

    if (close(input_fd) < 0) {
        input_fd = -1;
        goto done;
    }
    input_fd = -1;

    if (rename(temp_path, final_path) < 0)
        goto done;

    temp_created = 0;
    result = 0;

done:
    if (output_fd >= 0)
        close(output_fd);
    if (input_fd >= 0)
        close(input_fd);
    if (temp_created)
        unlink(temp_path);
    EVP_CIPHER_CTX_free(ctx);
    free(temp_path);
    free(final_path);
    return result;
}