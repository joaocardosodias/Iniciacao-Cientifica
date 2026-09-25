#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "config.h"

static int read_file(const char *path, unsigned char **buf, size_t *out_len) {
    int fd = -1;
    struct stat st;
    unsigned char *data = NULL;
    ssize_t r;
    size_t total = 0;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }
    if (st.st_size < 0) {
        close(fd);
        return -1;
    }
    data = malloc((size_t)st.st_size);
    if (!data) {
        close(fd);
        return -1;
    }
    while (total < (size_t)st.st_size) {
        r = read(fd, data + total, (size_t)st.st_size - total);
        if (r <= 0) {
            free(data);
            close(fd);
            return -1;
        }
        total += (size_t)r;
    }
    close(fd);
    *buf = data;
    *out_len = total;
    return 0;
}

static int write_all(int fd, const unsigned char *buf, size_t len) {
    size_t written = 0;
    ssize_t w;
    while (written < len) {
        w = write(fd, buf + written, len - written);
        if (w <= 0)
            return -1;
        written += (size_t)w;
    }
    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len) {
    unsigned char *plaintext = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char nonce[12];
    unsigned char tag[16];
    size_t plaintext_len = 0;
    size_t ciphertext_len = 0;
    int ret = -1;
    EVP_CIPHER_CTX *ctx = NULL;
    char *out_path = NULL;
    int out_fd = -1;
    int rc;

    if (!path || !key || key_len != 32)  /* AES-256 requires 32‑byte key */
        return -1;

    if (read_file(path, &plaintext, &plaintext_len) < 0)
        goto cleanup;

    ciphertext = malloc(plaintext_len);
    if (!ciphertext)
        goto cleanup;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1)
        goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)plaintext_len) != 1)
        goto cleanup;
    ciphertext_len = (size_t)outlen;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen) != 1)
        goto cleanup;
    ciphertext_len += (size_t)outlen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
        goto cleanup;

    /* Build output path */
    {
        size_t plen = strlen(path);
        size_t slen = strlen(ENCRYPTED_SUFFIX);
        out_path = malloc(plen + slen + 1);
        if (!out_path)
            goto cleanup;
        memcpy(out_path, path, plen);
        memcpy(out_path + plen, ENCRYPTED_SUFFIX, slen + 1);
    }

    out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0)
        goto cleanup;

    /* Write nonce, ciphertext, tag */
    if (write_all(out_fd, nonce, sizeof(nonce)) < 0)
        goto cleanup;
    if (write_all(out_fd, ciphertext, ciphertext_len) < 0)
        goto cleanup;
    if (write_all(out_fd, tag, sizeof(tag)) < 0)
        goto cleanup;

    ret = 0; /* success */

cleanup:
    if (out_fd >= 0)
        close(out_fd);
    if (out_path)
        free(out_path);
    if (ciphertext)
        free(ciphertext);
    if (plaintext)
        free(plaintext);
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return ret;
}