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
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "config.h"

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    if (!path || !key || key_len != 32) {
        errno = EINVAL;
        return -1;
    }

    int in_fd = -1, out_fd = -1;
    struct stat st;
    unsigned char *plaintext = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char nonce[12];
    unsigned char tag[16];
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = -1;
    size_t plaintext_len = 0;
    int len = 0;
    int out_len = 0;

     
    in_fd = open(path, O_RDONLY);
    if (in_fd < 0)
        goto cleanup;

    if (fstat(in_fd, &st) < 0)
        goto cleanup;

    plaintext_len = (size_t)st.st_size;
    plaintext = malloc(plaintext_len);
    if (!plaintext)
        goto cleanup;

     
    {
        size_t total = 0;
        ssize_t r;
        while (total < plaintext_len) {
            r = read(in_fd, plaintext + total, plaintext_len - total);
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                goto cleanup;
            }
            if (r == 0)
                break;
            total += (size_t)r;
        }
        if (total != plaintext_len) {
            errno = EIO;
            goto cleanup;
        }
    }

     
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

     
    if (EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, (int)plaintext_len) != 1)
        goto cleanup;
    out_len = len;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + out_len, &len) != 1)
        goto cleanup;
    out_len += len;

     
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
        goto cleanup;

     
    {
        size_t path_len = strlen(path);
        size_t suffix_len = strlen(ENCRYPTED_SUFFIX);
        char *out_path = malloc(path_len + suffix_len + 1);
        if (!out_path)
            goto cleanup;
        memcpy(out_path, path, path_len);
        memcpy(out_path + path_len, ENCRYPTED_SUFFIX, suffix_len + 1);

        out_fd = open(out_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
        free(out_path);
        if (out_fd < 0)
            goto cleanup;
    }

     
    {
        size_t total = 0;
        ssize_t w;
        while (total < sizeof(nonce)) {
            w = write(out_fd, nonce + total, sizeof(nonce) - total);
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                goto cleanup;
            }
            total += (size_t)w;
        }
    }

     
    {
        size_t total = 0;
        ssize_t w;
        while (total < (size_t)out_len) {
            w = write(out_fd, ciphertext + total, out_len - total);
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                goto cleanup;
            }
            total += (size_t)w;
        }
    }

     
    {
        size_t total = 0;
        ssize_t w;
        while (total < sizeof(tag)) {
            w = write(out_fd, tag + total, sizeof(tag) - total);
            if (w < 0) {
                if (errno == EINTR)
                    continue;
                goto cleanup;
            }
            total += (size_t)w;
        }
    }

    ret = 0;  

cleanup:
    if (in_fd >= 0)
        close(in_fd);
    if (out_fd >= 0)
        close(out_fd);
    if (plaintext)
        free(plaintext);
    if (ciphertext)
        free(ciphertext);
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return ret;
}