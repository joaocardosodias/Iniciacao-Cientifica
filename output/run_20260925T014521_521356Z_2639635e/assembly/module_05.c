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
#include <fcntl.h>
#include <sys/stat.h>
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

    if (st.st_size < 0) {
        close(fd);
        return -1;
    }

    buf = malloc((size_t)st.st_size);
    if (!buf) {
        close(fd);
        return -1;
    }

    while (total < (size_t)st.st_size) {
        r = read(fd, buf + total, (size_t)st.st_size - total);
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
    *out_buf = buf;
    *out_len = total;
    return 0;
}

static int write_all(int fd, const unsigned char *buf, size_t len)
{
    size_t written = 0;
    ssize_t w;

    while (written < len) {
        w = write(fd, buf + written, len - written);
        if (w < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        written += (size_t)w;
    }
    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    const size_t NONCE_LEN = 12;
    const size_t TAG_LEN = 16;
    unsigned char *plaintext = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char nonce[12];
    unsigned char tag[16];
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *out_path = NULL;
    int fd_out = -1;
    size_t plain_len = 0;
    int ret = -1;
    int rc;

    if (!path || !key || key_len != 32)
        return -1;

    if (read_file(path, &plaintext, &plain_len) < 0)
        goto cleanup;

    ciphertext = malloc(plain_len);
    if (!ciphertext)
        goto cleanup;

    if (RAND_bytes(nonce, NONCE_LEN) != 1)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)plain_len) != 1)
        goto cleanup;
    size_t ciphertext_len = (size_t)outlen;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen) != 1)
        goto cleanup;
    ciphertext_len += (size_t)outlen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1)
        goto cleanup;

    rc = asprintf((char **)&out_path, "%s" ENCRYPTED_SUFFIX, path);
    if (rc < 0 || !out_path)
        goto cleanup;

    fd_out = open((const char *)out_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (fd_out < 0)
        goto cleanup;

    if (write_all(fd_out, nonce, NONCE_LEN) < 0)
        goto cleanup;
    if (write_all(fd_out, ciphertext, ciphertext_len) < 0)
        goto cleanup;
    if (write_all(fd_out, tag, TAG_LEN) < 0)
        goto cleanup;

    ret = 0;

cleanup:
    if (fd_out >= 0)
        close(fd_out);
    if (out_path)
        free(out_path);
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    if (ciphertext)
        free(ciphertext);
    if (plaintext)
        free(plaintext);
    return ret;
}