#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#include "config.h"

#define GCM_NONCE_LEN 12
#define GCM_TAG_LEN 16
#define AES_256_KEY_LEN 32
#define ENC_CHUNK_LEN (1 << 30)

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
        off += (size_t)n;
    }
    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    int ret = -1;
    int fd = -1;
    int out_fd = -1;
    unsigned char *plaintext = NULL;
    unsigned char *ciphertext = NULL;
    char *out_path = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char nonce[GCM_NONCE_LEN];
    unsigned char tag[GCM_TAG_LEN];
    struct stat st;
    size_t file_size = 0;
    size_t ct_len = 0;
    size_t path_len;
    size_t suffix_len;
    int outl = 0;

    if (path == NULL || key == NULL || key_len != AES_256_KEY_LEN)
        return -1;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0)
        goto cleanup;
    if (st.st_size < 0)
        goto cleanup;
    file_size = (size_t)st.st_size;

    if (file_size > 0) {
        size_t total = 0;

        plaintext = malloc(file_size);
        if (plaintext == NULL)
            goto cleanup;
        while (total < file_size) {
            ssize_t n = read(fd, plaintext + total, file_size - total);
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                goto cleanup;
            }
            if (n == 0)
                goto cleanup;
            total += (size_t)n;
        }
    }

    if (RAND_bytes(nonce, GCM_NONCE_LEN) != 1)
        goto cleanup;

    ciphertext = malloc(file_size + EVP_MAX_BLOCK_LENGTH);
    if (ciphertext == NULL)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_LEN, NULL) != 1)
        goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    {
        size_t offset = 0;

        while (offset < file_size) {
            size_t want = file_size - offset;
            int chunk = (want > (size_t)ENC_CHUNK_LEN) ? ENC_CHUNK_LEN : (int)want;

            if (EVP_EncryptUpdate(ctx, ciphertext + ct_len, &outl,
                                  plaintext + offset, chunk) != 1)
                goto cleanup;
            ct_len += (size_t)outl;
            offset += (size_t)chunk;
        }
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + ct_len, &outl) != 1)
        goto cleanup;
    ct_len += (size_t)outl;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_LEN, tag) != 1)
        goto cleanup;

    path_len = strlen(path);
    suffix_len = strlen(ENCRYPTED_SUFFIX);
    out_path = malloc(path_len + suffix_len + 1);
    if (out_path == NULL)
        goto cleanup;
    memcpy(out_path, path, path_len);
    memcpy(out_path + path_len, ENCRYPTED_SUFFIX, suffix_len + 1);

    out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out_fd < 0)
        goto cleanup;

    if (write_all(out_fd, nonce, GCM_NONCE_LEN) < 0)
        goto cleanup;
    if (write_all(out_fd, ciphertext, ct_len) < 0)
        goto cleanup;
    if (write_all(out_fd, tag, GCM_TAG_LEN) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    if (out_fd >= 0) {
        if (close(out_fd) < 0)
            ret = -1;
    }
    if (ret != 0 && out_path != NULL)
        unlink(out_path);
    if (fd >= 0)
        close(fd);
    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    if (plaintext != NULL) {
        OPENSSL_cleanse(plaintext, file_size);
        free(plaintext);
    }
    if (ciphertext != NULL)
        free(ciphertext);
    if (out_path != NULL)
        free(out_path);
    return ret;
}