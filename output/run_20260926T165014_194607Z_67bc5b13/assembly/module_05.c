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

static int read_file(const char *path, unsigned char **out_buf, size_t *out_len) {
    int fd = -1;
    struct stat st;
    unsigned char *buf = NULL;
    ssize_t r;
    size_t total = 0;

    fd = open(path, O_RDONLY);
    if (fd < 0) return -1;
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
            if (errno == EINTR) continue;
            free(buf);
            close(fd);
            return -1;
        }
        if (r == 0) break;
        total += (size_t)r;
    }
    close(fd);
    *out_buf = buf;
    *out_len = total;
    return 0;
}

static int write_all(int fd, const unsigned char *buf, size_t len) {
    size_t written = 0;
    ssize_t w;
    while (written < len) {
        w = write(fd, buf + written, len - written);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        written += (size_t)w;
    }
    return 0;
}

static void remove_temp(const char *tmp_path) {
    if (tmp_path) {
        unlink(tmp_path);
    }
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len) {
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    unsigned char *ciphertext = NULL;
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char *outbuf = NULL;
    size_t out_len = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = -1;
    char *tmp_path = NULL;
    char *final_path = NULL;
    int out_fd = -1;

    if (!path || !key) {
        return -1;
    }
    if (read_file(path, &plaintext, &plaintext_len) < 0) {
        goto cleanup;
    }
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        goto cleanup;
    }
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1) {
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        goto cleanup;
    }
    ciphertext = malloc(plaintext_len);
    if (!ciphertext) {
        goto cleanup;
    }
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)plaintext_len) != 1) {
        goto cleanup;
    }
    int tmplen = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen) != 1) {
        goto cleanup;
    }
    outlen += tmplen;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        goto cleanup;
    }
    out_len = 1 + sizeof(nonce) + (size_t)outlen + sizeof(tag);
    outbuf = malloc(out_len);
    if (!outbuf) {
        goto cleanup;
    }
    outbuf[0] = ENCRYPTED_FORMAT_VERSION;
    memcpy(outbuf + 1, nonce, sizeof(nonce));
    memcpy(outbuf + 1 + sizeof(nonce), ciphertext, (size_t)outlen);
    memcpy(outbuf + 1 + sizeof(nonce) + (size_t)outlen, tag, sizeof(tag));

    if (asprintf(&tmp_path, "%s%s.tmp", path, ENCRYPTED_SUFFIX) < 0) {
        goto cleanup;
    }
    if (asprintf(&final_path, "%s%s", path, ENCRYPTED_SUFFIX) < 0) {
        goto cleanup;
    }

    out_fd = open(tmp_path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    if (out_fd < 0) {
        goto cleanup;
    }
    if (write_all(out_fd, outbuf, out_len) < 0) {
        goto cleanup;
    }
    if (fsync(out_fd) < 0) {
        goto cleanup;
    }
    close(out_fd);
    out_fd = -1;
    if (rename(tmp_path, final_path) < 0) {
        goto cleanup;
    }
    ret = 0;
cleanup:
    if (out_fd >= 0) close(out_fd);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (plaintext) {
        OPENSSL_cleanse(plaintext, plaintext_len);
        free(plaintext);
    }
    if (ciphertext) {
        OPENSSL_cleanse(ciphertext, plaintext_len);
        free(ciphertext);
    }
    if (outbuf) {
        OPENSSL_cleanse(outbuf, out_len);
        free(outbuf);
    }
    if (tmp_path) {
        if (ret != 0) remove_temp(tmp_path);
        free(tmp_path);
    }
    if (final_path) free(final_path);
    return ret;
}