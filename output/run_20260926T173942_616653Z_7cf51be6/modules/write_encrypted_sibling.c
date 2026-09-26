#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "config.h"

static int read_file(const char *path, unsigned char **out_buf, size_t *out_len)
{
    int fd = -1;
    struct stat st;
    unsigned char *buf = NULL;
    ssize_t r;
    size_t total = 0;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }

    buf = malloc(st.st_size);
    if (!buf) {
        close(fd);
        return -1;
    }

    while (total < (size_t)st.st_size) {
        r = read(fd, buf + total, st.st_size - total);
        if (r < 0) {
            free(buf);
            close(fd);
            return -1;
        }
        if (r == 0)
            break;
        total += r;
    }

    close(fd);
    *out_buf = buf;
    *out_len = total;
    return 0;
}

static int encrypt_aes_gcm(const unsigned char *plaintext, size_t pt_len,
                           const unsigned char *key, size_t key_len,
                           unsigned char **out_buf, size_t *out_len,
                           unsigned char *nonce_out)
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *ciphertext = NULL;
    int len, ciphertext_len;
    unsigned char tag[16];
    int ret = -1;

    if (key_len != 32 || RAND_bytes(nonce_out, 12) != 1)
        return -1;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        return -1;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce_out) != 1)
        goto cleanup;

    ciphertext = malloc(pt_len);
    if (!ciphertext)
        goto cleanup;

    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, pt_len) != 1)
        goto cleanup;
    ciphertext_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + len, &len) != 1)
        goto cleanup;
    ciphertext_len += len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
        goto cleanup;

    /* Build output: version | nonce | ciphertext | tag */
    *out_len = 1 + 12 + ciphertext_len + 16;
    *out_buf = malloc(*out_len);
    if (!*out_buf)
        goto cleanup;

    (*out_buf)[0] = ENCRYPTED_FORMAT_VERSION;
    memcpy(*out_buf + 1, nonce_out, 12);
    memcpy(*out_buf + 1 + 12, ciphertext, ciphertext_len);
    memcpy(*out_buf + 1 + 12 + ciphertext_len, tag, 16);

    ret = 0;

cleanup:
    if (ciphertext)
        free(ciphertext);
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int write_file_atomic(const char *final_path, const unsigned char *data, size_t data_len)
{
    char *temp_path = NULL;
    int fd = -1;
    ssize_t w;
    size_t written = 0;
    int ret = -1;

    size_t final_len = strlen(final_path);
    temp_path = malloc(final_len + strlen(".tmp") + 1);
    if (!temp_path)
        return -1;
    memcpy(temp_path, final_path, final_len);
    memcpy(temp_path + final_len, ".tmp", 5);
    temp_path[final_len + 4] = '\0';

    fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        goto cleanup;

    while (written < data_len) {
        w = write(fd, data + written, data_len - written);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        written += w;
    }

    if (fsync(fd) < 0)
        goto cleanup;

    if (close(fd) < 0) {
        fd = -1;
        goto cleanup;
    }
    fd = -1;

    if (rename(temp_path, final_path) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    if (fd >= 0)
        close(fd);
    if (ret != 0 && temp_path)
        unlink(temp_path);
    if (temp_path)
        free(temp_path);
    return ret;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    unsigned char nonce[12];
    unsigned char *out_buf = NULL;
    size_t out_len = 0;
    char *final_path = NULL;
    int ret = -1;

    if (!path || !key)
        return -1;

    if (read_file(path, &plaintext, &plaintext_len) < 0)
        goto cleanup;

    if (encrypt_aes_gcm(plaintext, plaintext_len, key, key_len,
                       &out_buf, &out_len, nonce) < 0)
        goto cleanup;

    final_path = malloc(strlen(path) + strlen(ENCRYPTED_SUFFIX) + 1);
    if (!final_path)
        goto cleanup;
    strcpy(final_path, path);
    strcat(final_path, ENCRYPTED_SUFFIX);

    if (write_file_atomic(final_path, out_buf, out_len) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    if (plaintext)
        free(plaintext);
    if (out_buf)
        free(out_buf);
    if (final_path)
        free(final_path);
    return ret;
}