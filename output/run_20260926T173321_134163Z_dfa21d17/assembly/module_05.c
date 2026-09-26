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
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <fcntl.h>
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
    *out_len = (size_t)st.st_size;
    buf = malloc(*out_len);
    if (!buf) {
        close(fd);
        return -1;
    }
    while (total < *out_len) {
        r = read(fd, buf + total, *out_len - total);
        if (r < 0) {
            if (errno == EINTR)
                continue;
            free(buf);
            close(fd);
            return -1;
        }
        if (r == 0)
            break;
        total += (size_t)r;
    }
    close(fd);
    if (total != *out_len) {
        free(buf);
        return -1;
    }
    *out_buf = buf;
    return 0;
}

static int encrypt_aes256_gcm(const unsigned char *plaintext, size_t pt_len,
                              const unsigned char *key, size_t key_len,
                              unsigned char nonce[12],
                              unsigned char **out_cipher, size_t *out_len,
                              unsigned char tag[16])
{
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *cipher = NULL;
    int len = 0, ret = -1;

    if (key_len != 32)
        return -1;
    if (RAND_bytes(nonce, 12) != 1)
        return -1;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
        goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    cipher = malloc(pt_len);
    if (!cipher)
        goto cleanup;

    if (EVP_EncryptUpdate(ctx, cipher, &len, plaintext, (int)pt_len) != 1)
        goto cleanup;
    *out_len = (size_t)len;

    if (EVP_EncryptFinal_ex(ctx, cipher + len, &len) != 1)
        goto cleanup;
    *out_len += (size_t)len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
        goto cleanup;

    *out_cipher = cipher;
    cipher = NULL;
    ret = 0;

cleanup:
    if (cipher)
        free(cipher);
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    return ret;
}

static int write_temp_and_rename(const char *final_path, const unsigned char *data, size_t data_len)
{
    char *tmp_path = NULL;
    int fd = -1;
    ssize_t w;
    size_t written = 0;
    int ret = -1;

    tmp_path = malloc(strlen(final_path) + 5);  
    if (!tmp_path)
        return -1;
    strcpy(tmp_path, final_path);
    strcat(tmp_path, ".tmp");

    fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd < 0)
        goto cleanup;

    while (written < data_len) {
        w = write(fd, data + written, data_len - written);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        written += (size_t)w;
    }
    if (fsync(fd) < 0)
        goto cleanup;
    if (close(fd) < 0) {
        fd = -1;
        goto cleanup;
    }
    fd = -1;

    if (rename(tmp_path, final_path) != 0)
        goto cleanup;

    ret = 0;

cleanup:
    if (fd >= 0)
        close(fd);
    if (tmp_path) {
        if (ret != 0)
            unlink(tmp_path);
        free(tmp_path);
    }
    return ret;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    unsigned char *plaintext = NULL;
    size_t pt_len = 0;
    unsigned char nonce[12];
    unsigned char *cipher = NULL;
    size_t cipher_len = 0;
    unsigned char tag[16];
    unsigned char *out_buf = NULL;
    size_t out_len = 0;
    char *final_path = NULL;
    int rc = -1;

    if (read_file(path, &plaintext, &pt_len) < 0)
        goto cleanup;

    if (encrypt_aes256_gcm(plaintext, pt_len, key, key_len, nonce, &cipher, &cipher_len, tag) < 0)
        goto cleanup;

    out_len = 1 + 12 + cipher_len + 16;
    out_buf = malloc(out_len);
    if (!out_buf)
        goto cleanup;

    out_buf[0] = ENCRYPTED_FORMAT_VERSION;
    memcpy(out_buf + 1, nonce, 12);
    memcpy(out_buf + 1 + 12, cipher, cipher_len);
    memcpy(out_buf + 1 + 12 + cipher_len, tag, 16);

    final_path = malloc(strlen(path) + strlen(ENCRYPTED_SUFFIX) + 1);
    if (!final_path)
        goto cleanup;
    strcpy(final_path, path);
    strcat(final_path, ENCRYPTED_SUFFIX);

    if (write_temp_and_rename(final_path, out_buf, out_len) < 0)
        goto cleanup;

    rc = 0;

cleanup:
    if (plaintext)
        free(plaintext);
    if (cipher)
        free(cipher);
    if (out_buf)
        free(out_buf);
    if (final_path)
        free(final_path);
    return rc;
}