#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int write_all_fd(int fd, const unsigned char *buf, size_t len)
{
    size_t written = 0;

    while (written < len) {
        ssize_t n = write(fd, buf + written, len - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        written += (size_t)n;
    }
    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    int in_fd = -1;
    int out_fd = -1;
    int temp_created = 0;
    int result = -1;
    char *final_name = NULL;
    char *temp_name = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char nonce[12];
    unsigned char header[13];
    unsigned char inbuf[65536];
    unsigned char outbuf[65536 + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[16];

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    if (asprintf(&final_name, "%s%s", path, ENCRYPTED_SUFFIX) < 0)
        goto cleanup;
    if (asprintf(&temp_name, "%s.tmp", final_name) < 0)
        goto cleanup;

    in_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (in_fd < 0)
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

    out_fd = open(temp_name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (out_fd < 0)
        goto cleanup;
    temp_created = 1;

    header[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    memcpy(header + 1, nonce, sizeof(nonce));
    if (write_all_fd(out_fd, header, sizeof(header)) < 0)
        goto cleanup;

    for (;;) {
        ssize_t n = read(in_fd, inbuf, sizeof(inbuf));
        int out_len = 0;

        if (n < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        if (n == 0)
            break;
        if (EVP_EncryptUpdate(ctx, outbuf, &out_len, inbuf, (int)n) != 1)
            goto cleanup;
        if (write_all_fd(out_fd, outbuf, (size_t)out_len) < 0)
            goto cleanup;
    }

    if (close(in_fd) < 0) {
        in_fd = -1;
        goto cleanup;
    }
    in_fd = -1;

    {
        int out_len = 0;
        if (EVP_EncryptFinal_ex(ctx, outbuf, &out_len) != 1)
            goto cleanup;
        if (write_all_fd(out_fd, outbuf, (size_t)out_len) < 0)
            goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
        goto cleanup;
    if (write_all_fd(out_fd, tag, sizeof(tag)) < 0)
        goto cleanup;
    if (fsync(out_fd) < 0)
        goto cleanup;
    if (close(out_fd) < 0) {
        out_fd = -1;
        goto cleanup;
    }
    out_fd = -1;

    if (rename(temp_name, final_name) < 0)
        goto cleanup;
    temp_created = 0;
    result = 0;

cleanup:
    if (in_fd >= 0)
        close(in_fd);
    if (out_fd >= 0)
        close(out_fd);
    if (temp_created)
        unlink(temp_name);
    EVP_CIPHER_CTX_free(ctx);
    free(temp_name);
    free(final_name);
    return result;
}