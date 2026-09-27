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
    unsigned char nonce[12];
    unsigned char inbuf[65536];
    unsigned char outbuf[65536 + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[16];
    unsigned char version = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    char *final_path = NULL;
    char *temp_path = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int input_fd = -1;
    int temp_fd = -1;
    int temp_created = 0;
    int result = -1;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    if (asprintf(&final_path, "%s%s", path, ENCRYPTED_SUFFIX) < 0)
        goto out;
    if (asprintf(&temp_path, "%s.tmp", final_path) < 0)
        goto out;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto out;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto out;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto out;

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto out;

    temp_fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (temp_fd < 0)
        goto out;
    temp_created = 1;

    if (write_all(temp_fd, &version, 1) != 0 ||
        write_all(temp_fd, nonce, sizeof(nonce)) != 0)
        goto out;

    for (;;) {
        ssize_t nread = read(input_fd, inbuf, sizeof(inbuf));
        int out_len = 0;

        if (nread < 0) {
            if (errno == EINTR)
                continue;
            goto out;
        }
        if (nread == 0)
            break;
        if (EVP_EncryptUpdate(ctx, outbuf, &out_len, inbuf, (int)nread) != 1 ||
            write_all(temp_fd, outbuf, (size_t)out_len) != 0)
            goto out;
    }

    if (close(input_fd) != 0) {
        input_fd = -1;
        goto out;
    }
    input_fd = -1;

    {
        int out_len = 0;
        if (EVP_EncryptFinal_ex(ctx, outbuf, &out_len) != 1 ||
            write_all(temp_fd, outbuf, (size_t)out_len) != 0)
            goto out;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1 ||
        write_all(temp_fd, tag, sizeof(tag)) != 0)
        goto out;

    while (fsync(temp_fd) != 0) {
        if (errno != EINTR)
            goto out;
    }
    if (close(temp_fd) != 0) {
        temp_fd = -1;
        goto out;
    }
    temp_fd = -1;

    if (rename(temp_path, final_path) != 0)
        goto out;

    temp_created = 0;
    result = 0;

out:
    if (input_fd >= 0)
        close(input_fd);
    if (temp_fd >= 0)
        close(temp_fd);
    if (temp_created)
        unlink(temp_path);
    EVP_CIPHER_CTX_free(ctx);
    free(temp_path);
    free(final_path);
    return result;
}