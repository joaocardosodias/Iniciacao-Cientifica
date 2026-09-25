#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "config.h"

static ssize_t full_write(int fd, const void *buf, size_t count) {
    const unsigned char *p = buf;
    size_t remaining = count;
    while (remaining) {
        ssize_t w = write(fd, p, remaining);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        p += w;
        remaining -= w;
    }
    return count;
}

static ssize_t full_read(int fd, void *buf, size_t count) {
    unsigned char *p = buf;
    size_t remaining = count;
    while (remaining) {
        ssize_t r = read(fd, p, remaining);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break;
        p += r;
        remaining -= r;
    }
    return count - remaining;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len) {
    if (!path || !key || key_len != 32) {
        errno = EINVAL;
        return -1;
    }

    struct stat st;
    if (stat(path, &st) != 0) {
        return -1;
    }

    size_t plaintext_len = (size_t)st.st_size;
    unsigned char *plaintext = malloc(plaintext_len);
    if (!plaintext) {
        return -1;
    }

    int in_fd = open(path, O_RDONLY);
    if (in_fd < 0) {
        free(plaintext);
        return -1;
    }

    if (full_read(in_fd, plaintext, plaintext_len) != (ssize_t)plaintext_len) {
        close(in_fd);
        free(plaintext);
        return -1;
    }
    close(in_fd);

    unsigned char nonce[12];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        free(plaintext);
        return -1;
    }

    unsigned char *ciphertext = malloc(plaintext_len);
    if (!ciphertext) {
        free(plaintext);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(plaintext);
        free(ciphertext);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        free(ciphertext);
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        free(ciphertext);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        free(ciphertext);
        return -1;
    }

    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)plaintext_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        free(ciphertext);
        return -1;
    }
    int tmplen = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        free(ciphertext);
        return -1;
    }
    int ciphertext_len = outlen + tmplen;

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        free(ciphertext);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);

    size_t out_path_len = strlen(path) + strlen(ENCRYPTED_SUFFIX) + 1;
    char *out_path = malloc(out_path_len);
    if (!out_path) {
        free(ciphertext);
        return -1;
    }
    snprintf(out_path, out_path_len, "%s%s", path, ENCRYPTED_SUFFIX);

    int out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    free(out_path);
    if (out_fd < 0) {
        free(ciphertext);
        return -1;
    }

    if (full_write(out_fd, nonce, sizeof(nonce)) != sizeof(nonce) ||
        full_write(out_fd, ciphertext, ciphertext_len) != ciphertext_len ||
        full_write(out_fd, tag, sizeof(tag)) != sizeof(tag)) {
        close(out_fd);
        free(ciphertext);
        return -1;
    }

    close(out_fd);
    free(ciphertext);
    return 0;
}