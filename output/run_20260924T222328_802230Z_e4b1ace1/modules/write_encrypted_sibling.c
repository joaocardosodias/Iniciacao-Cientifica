#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

static unsigned char *read_all(const char *path, size_t *out_len)
{
    int fd = open(path, O_RDONLY);
    if (fd < 0)
        return NULL;

    struct stat st;
    if (fstat(fd, &st) != 0 || !S_ISREG(st.st_mode)) {
        close(fd);
        return NULL;
    }

    size_t cap = (size_t)st.st_size;
    unsigned char *buf = malloc(cap ? cap : 1);
    if (!buf) {
        close(fd);
        return NULL;
    }

    size_t total = 0;
    while (total < cap) {
        ssize_t r = read(fd, buf + total, cap - total);
        if (r < 0) {
            free(buf);
            close(fd);
            return NULL;
        }
        if (r == 0)
            break;
        total += (size_t)r;
    }

    close(fd);
    *out_len = total;
    return buf;
}

static int write_all(int fd, const unsigned char *buf, size_t len)
{
    size_t total = 0;
    while (total < len) {
        ssize_t w = write(fd, buf + total, len - total);
        if (w < 0)
            return -1;
        total += (size_t)w;
    }
    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    if (!path || !key || key_len != 32)
        return -1;

    size_t plain_len = 0;
    unsigned char *plain = read_all(path, &plain_len);
    if (!plain)
        return -1;

    unsigned char nonce[12];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        free(plain);
        return -1;
    }

    unsigned char tag[16];
    unsigned char *cipher = malloc(plain_len ? plain_len : 1);
    if (!cipher) {
        free(plain);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(cipher);
        free(plain);
        return -1;
    }

    int ok = 0;
    int outlen = 0;
    int cipher_len = 0;

    do {
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
            break;
        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(nonce), NULL) != 1)
            break;
        if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
            break;

        if (plain_len > 0) {
            if (EVP_EncryptUpdate(ctx, cipher, &outlen, plain, (int)plain_len) != 1)
                break;
            cipher_len = outlen;
        }

        if (EVP_EncryptFinal_ex(ctx, cipher + cipher_len, &outlen) != 1)
            break;
        cipher_len += outlen;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)sizeof(tag), tag) != 1)
            break;

        ok = 1;
    } while (0);

    EVP_CIPHER_CTX_free(ctx);
    free(plain);

    if (!ok) {
        free(cipher);
        return -1;
    }

    size_t path_len = strlen(path);
    size_t suf_len = strlen(ENCRYPTED_SUFFIX);
    char *out_path = malloc(path_len + suf_len + 1);
    if (!out_path) {
        free(cipher);
        return -1;
    }
    memcpy(out_path, path, path_len);
    memcpy(out_path + path_len, ENCRYPTED_SUFFIX, suf_len);
    out_path[path_len + suf_len] = '\0';

    int fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    free(out_path);
    if (fd < 0) {
        free(cipher);
        return -1;
    }

    int rc = 0;
    if (write_all(fd, nonce, sizeof(nonce)) != 0)
        rc = -1;
    if (rc == 0 && cipher_len > 0 && write_all(fd, cipher, (size_t)cipher_len) != 0)
        rc = -1;
    if (rc == 0 && write_all(fd, tag, sizeof(tag)) != 0)
        rc = -1;

    if (close(fd) != 0)
        rc = -1;

    free(cipher);
    return rc;
}