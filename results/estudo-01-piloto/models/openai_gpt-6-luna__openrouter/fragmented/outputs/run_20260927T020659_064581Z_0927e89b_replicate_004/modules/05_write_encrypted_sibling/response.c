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

static int write_all(int fd, const unsigned char *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = write(fd, buf + off, len - off);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        off += (size_t)n;
    }
    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    int in_fd = -1;
    int out_fd = -1;
    int result = -1;
    char *final_path = NULL;
    char *tmp_path = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char version;
    unsigned char inbuf[65536];
    unsigned char outbuf[65536 + EVP_MAX_BLOCK_LENGTH];
    unsigned char header[13];
    unsigned char finalbuf[EVP_MAX_BLOCK_LENGTH];
    int out_len;
    int final_len;

    if (path == NULL || key == NULL || key_len != 32) {
        errno = EINVAL;
        return -1;
    }

    if (asprintf(&final_path, "%s%s", path, ENCRYPTED_SUFFIX) < 0)
        goto done;
    if (asprintf(&tmp_path, "%s.tmp", final_path) < 0)
        goto done;

    in_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (in_fd < 0)
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

    out_fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW, 0600);
    if (out_fd < 0)
        goto done;

    version = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    header[0] = version;
    memcpy(header + 1, nonce, sizeof(nonce));
    if (write_all(out_fd, header, sizeof(header)) < 0)
        goto done;

    for (;;) {
        ssize_t n = read(in_fd, inbuf, sizeof(inbuf));
        if (n < 0) {
            if (errno == EINTR)
                continue;
            goto done;
        }
        if (n == 0)
            break;
        if (EVP_EncryptUpdate(ctx, outbuf, &out_len, inbuf, (int)n) != 1)
            goto done;
        if (out_len > 0 && write_all(out_fd, outbuf, (size_t)out_len) < 0)
            goto done;
    }

    if (EVP_EncryptFinal_ex(ctx, finalbuf, &final_len) != 1)
        goto done;
    if (final_len > 0 && write_all(out_fd, finalbuf, (size_t)final_len) < 0)
        goto done;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
        goto done;
    if (write_all(out_fd, tag, sizeof(tag)) < 0)
        goto done;

    if (fsync(out_fd) < 0)
        goto done;
    if (close(out_fd) < 0) {
        out_fd = -1;
        goto done;
    }
    out_fd = -1;

    if (close(in_fd) < 0) {
        in_fd = -1;
        goto done;
    }
    in_fd = -1;

    if (rename(tmp_path, final_path) < 0)
        goto done;

    result = 0;

done:
    if (out_fd >= 0)
        close(out_fd);
    if (in_fd >= 0)
        close(in_fd);
    if (result != 0 && tmp_path != NULL)
        unlink(tmp_path);
    EVP_CIPHER_CTX_free(ctx);
    free(tmp_path);
    free(final_path);
    return result;
}