#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "config.h"

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len) {
    int ret = -1;
    int fd_in = -1, fd_out = -1;
    struct stat st;
    unsigned char *plaintext = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char iv[12];
    unsigned char tag[16];
    EVP_CIPHER_CTX *ctx = NULL;
    char *out_path = NULL;
    size_t out_path_len;

    if (!path || !key || key_len != 32) {
        errno = EINVAL;
        return -1;
    }

    if (stat(path, &st) < 0)
        goto cleanup;
    if (!S_ISREG(st.st_mode))
        goto cleanup;

    plaintext = malloc(st.st_size);
    if (!plaintext)
        goto cleanup;

    fd_in = open(path, O_RDONLY);
    if (fd_in < 0)
        goto cleanup;

    ssize_t rd = 0;
    size_t total = 0;
    while (total < (size_t)st.st_size) {
        rd = read(fd_in, plaintext + total, (size_t)st.st_size - total);
        if (rd <= 0) {
            if (rd == -1 && errno == EINTR) continue;
            goto cleanup;
        }
        total += (size_t)rd;
    }

    if (RAND_bytes(iv, sizeof(iv)) != 1)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(iv), NULL) != 1)
        goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, iv) != 1)
        goto cleanup;

    ciphertext = malloc(st.st_size);
    if (!ciphertext)
        goto cleanup;

    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)st.st_size) != 1)
        goto cleanup;
    int ciphertext_len = outlen;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen) != 1)
        goto cleanup;
    ciphertext_len += outlen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
        goto cleanup;

    out_path_len = strlen(path) + strlen(ENCRYPTED_SUFFIX) + 1;
    out_path = malloc(out_path_len);
    if (!out_path)
        goto cleanup;
    snprintf(out_path, out_path_len, "%s%s", path, ENCRYPTED_SUFFIX);

    fd_out = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd_out < 0)
        goto cleanup;

    if (write(fd_out, iv, sizeof(iv)) != (ssize_t)sizeof(iv))
        goto cleanup;
    if (write(fd_out, ciphertext, (size_t)ciphertext_len) != (ssize_t)ciphertext_len)
        goto cleanup;
    if (write(fd_out, tag, sizeof(tag)) != (ssize_t)sizeof(tag))
        goto cleanup;

    ret = 0;

cleanup:
    if (fd_in >= 0) close(fd_in);
    if (fd_out >= 0) close(fd_out);
    if (plaintext) {
        OPENSSL_cleanse(plaintext, st.st_size);
        free(plaintext);
    }
    if (ciphertext) {
        OPENSSL_cleanse(ciphertext, st.st_size);
        free(ciphertext);
    }
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (out_path) free(out_path);
    return ret;
}