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
#include <errno.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include "config.h"

static int read_file(const char *path, unsigned char **out_buf, size_t *out_len) {
    FILE *fp = fopen(path, "rb");
    if (!fp) return -1;
    if (fseek(fp, 0, SEEK_END) != 0) {
        fclose(fp);
        return -1;
    }
    long sz = ftell(fp);
    if (sz < 0) {
        fclose(fp);
        return -1;
    }
    rewind(fp);
    unsigned char *buf = malloc((size_t)sz);
    if (!buf) {
        fclose(fp);
        return -1;
    }
    size_t read = fread(buf, 1, (size_t)sz, fp);
    fclose(fp);
    if (read != (size_t)sz) {
        free(buf);
        return -1;
    }
    *out_buf = buf;
    *out_len = (size_t)sz;
    return 0;
}

static int write_file(const char *path, const unsigned char *nonce, const unsigned char *cipher, size_t cipher_len, const unsigned char *tag) {
    FILE *fp = fopen(path, "wb");
    if (!fp) return -1;
    if (fwrite(nonce, 1, 12, fp) != 12) {
        fclose(fp);
        return -1;
    }
    if (fwrite(cipher, 1, cipher_len, fp) != cipher_len) {
        fclose(fp);
        return -1;
    }
    if (fwrite(tag, 1, 16, fp) != 16) {
        fclose(fp);
        return -1;
    }
    if (fflush(fp) != 0) {
        fclose(fp);
        return -1;
    }
    fclose(fp);
    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len) {
    if (!path || !key || key_len != 32) return -1;

    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    if (read_file(path, &plaintext, &plaintext_len) != 0) {
        return -1;
    }

    unsigned char nonce[12];
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        free(plaintext);
        return -1;
    }

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        free(plaintext);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return -1;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return -1;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return -1;
    }

    unsigned char *ciphertext = malloc(plaintext_len);
    if (!ciphertext) {
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return -1;
    }

    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, (int)plaintext_len) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return -1;
    }

    int tmplen = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &tmplen) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return -1;
    }
    outlen += tmplen;

    unsigned char tag[16];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        free(ciphertext);
        EVP_CIPHER_CTX_free(ctx);
        free(plaintext);
        return -1;
    }

    EVP_CIPHER_CTX_free(ctx);
    free(plaintext);

    size_t path_len = strlen(path);
    size_t suffix_len = strlen(ENCRYPTED_SUFFIX);
    char *out_path = malloc(path_len + suffix_len + 1);
    if (!out_path) {
        free(ciphertext);
        return -1;
    }
    memcpy(out_path, path, path_len);
    memcpy(out_path + path_len, ENCRYPTED_SUFFIX, suffix_len + 1);

    int ret = write_file(out_path, nonce, ciphertext, (size_t)outlen, tag);
    free(out_path);
    free(ciphertext);
    return ret == 0 ? 0 : -1;
}