#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <syslog.h>
#include <wchar.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "config.h"

static ssize_t full_read(int fd, unsigned char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t r = read(fd, buf + total, len - total);
        if (r < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (r == 0) break;
        total += r;
    }
    return total == len ? (ssize_t)total : -1;
}

static ssize_t full_write(int fd, const unsigned char *buf, size_t len) {
    size_t total = 0;
    while (total < len) {
        ssize_t w = write(fd, buf + total, len - total);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        total += w;
    }
    return (ssize_t)total;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len) {
    int ret = -1;
    int fd_in = -1, fd_out = -1;
    struct stat st;
    unsigned char *plaintext = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char *outbuf = NULL;
    char *final_name = NULL;
    char *temp_name = NULL;

    if (!path || !key || key_len != 32) {
        errno = EINVAL;
        return -1;
    }

     
    if (asprintf(&final_name, "%s%s", path, ENCRYPTED_SUFFIX) < 0) goto cleanup;
    if (asprintf(&temp_name, "%s.tmp", final_name) < 0) goto cleanup;

     
    fd_in = open(path, O_RDONLY);
    if (fd_in < 0) goto cleanup;
    if (fstat(fd_in, &st) < 0) goto cleanup;
    if (st.st_size < 0) goto cleanup;

    size_t plain_len = (size_t)st.st_size;
    plaintext = malloc(plain_len);
    if (!plaintext) goto cleanup;

    if (full_read(fd_in, plaintext, plain_len) < 0) goto cleanup;

     
    unsigned char nonce[12];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) goto cleanup;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto cleanup;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        goto cleanup;
    }

    ciphertext = malloc(plain_len);
    if (!ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        goto cleanup;
    }
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)plain_len) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        goto cleanup;
    }
    int ciphertext_len = outlen;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        goto cleanup;
    }
    ciphertext_len += outlen;

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        goto cleanup;
    }
    EVP_CIPHER_CTX_free(ctx);

     
    size_t out_size = 1 + sizeof(nonce) + ciphertext_len + sizeof(tag);
    outbuf = malloc(out_size);
    if (!outbuf) goto cleanup;

    outbuf[0] = ENCRYPTED_FORMAT_VERSION;
    memcpy(outbuf + 1, nonce, sizeof(nonce));
    memcpy(outbuf + 1 + sizeof(nonce), ciphertext, ciphertext_len);
    memcpy(outbuf + 1 + sizeof(nonce) + ciphertext_len, tag, sizeof(tag));

     
    fd_out = open(temp_name, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (fd_out < 0) goto cleanup;
    if (full_write(fd_out, outbuf, out_size) != (ssize_t)out_size) goto cleanup;
    if (fsync(fd_out) < 0) goto cleanup;
    if (close(fd_out) < 0) {
        fd_out = -1;
        goto cleanup;
    }
    fd_out = -1;

     
    if (rename(temp_name, final_name) < 0) goto cleanup;

    ret = 0;   

cleanup:
    if (fd_in >= 0) close(fd_in);
    if (fd_out >= 0) close(fd_out);
    if (plaintext) {
        OPENSSL_cleanse(plaintext, plain_len);
        free(plaintext);
    }
    if (ciphertext) {
        OPENSSL_cleanse(ciphertext, plain_len);
        free(ciphertext);
    }
    if (outbuf) {
        OPENSSL_cleanse(outbuf, out_size);
        free(outbuf);
    }
    if (temp_name) {
        if (ret != 0) unlink(temp_name);
        free(temp_name);
    }
    if (final_name) free(final_name);
    return ret;
}