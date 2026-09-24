#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

static int
write_all_fd(int fd, const unsigned char *buf, size_t len)
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
    unsigned char outbuf[65552];
    unsigned char tag[16];
    EVP_CIPHER_CTX *ctx = NULL;
    char *output_path = NULL;
    char *temp_path = NULL;
    int input_fd = -1;
    int output_fd = -1;
    int temp_created = 0;
    int result = -1;
    int out_len;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    if (asprintf(&output_path, "%s%s", path, ENCRYPTED_SUFFIX) < 0)
        return -1;
    if (asprintf(&temp_path, "%s.tmp.XXXXXX", output_path) < 0)
        goto done;

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto done;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto done;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto done;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto done;

    output_fd = mkstemp(temp_path);
    if (output_fd < 0)
        goto done;
    temp_created = 1;

    if (write_all_fd(output_fd, nonce, sizeof(nonce)) < 0)
        goto done;

    for (;;) {
        ssize_t n = read(input_fd, inbuf, sizeof(inbuf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            goto done;
        }
        if (n == 0)
            break;

        if (EVP_EncryptUpdate(ctx, outbuf, &out_len, inbuf, (int)n) != 1)
            goto done;
        if (write_all_fd(output_fd, outbuf, (size_t)out_len) < 0)
            goto done;
    }

    if (EVP_EncryptFinal_ex(ctx, outbuf, &out_len) != 1)
        goto done;
    if (write_all_fd(output_fd, outbuf, (size_t)out_len) < 0)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
        goto done;
    if (write_all_fd(output_fd, tag, sizeof(tag)) < 0)
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

    if (rename(temp_path, output_path) < 0)
        goto done;
    temp_created = 0;
    result = 0;

done:
    if (input_fd >= 0)
        close(input_fd);
    if (output_fd >= 0)
        close(output_fd);
    if (temp_created)
        unlink(temp_path);
    EVP_CIPHER_CTX_free(ctx);
    free(temp_path);
    free(output_path);
    return result;
}