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
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    FILE *fin = NULL;
    FILE *fout = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *ciphertext = NULL;
    char *outpath = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int ret = -1;

    unsigned char nonce[12];
    unsigned char tag[16];

     
    fin = fopen(path, "rb");
    if (!fin) {
        goto cleanup;
    }

    if (fseek(fin, 0, SEEK_END) != 0) {
        goto cleanup;
    }
    long fsz = ftell(fin);
    if (fsz < 0) {
        goto cleanup;
    }
    rewind(fin);

    size_t plaintext_len = (size_t)fsz;
    plaintext = (unsigned char *)malloc(plaintext_len + 1);
    if (!plaintext && plaintext_len > 0) {
        goto cleanup;
    }

    if (plaintext_len > 0) {
        if (fread(plaintext, 1, plaintext_len, fin) != plaintext_len) {
            goto cleanup;
        }
    }
    fclose(fin);
    fin = NULL;

     
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        goto cleanup;
    }

     
    ciphertext = (unsigned char *)malloc(plaintext_len + 1);
    if (!ciphertext && plaintext_len > 0) {
        goto cleanup;
    }

     
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        goto cleanup;
    }

    int out_len = 0;
    int total_out = 0;

    if (plaintext_len > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &out_len, plaintext, (int)plaintext_len) != 1) {
            goto cleanup;
        }
        total_out = out_len;
    }

    int final_len = 0;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + total_out, &final_len) != 1) {
        goto cleanup;
    }
    total_out += final_len;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        goto cleanup;
    }

     
    size_t pathlen = strlen(path);
    size_t suffixlen = strlen(ENCRYPTED_SUFFIX);
    outpath = (char *)malloc(pathlen + suffixlen + 1);
    if (!outpath) {
        goto cleanup;
    }
    memcpy(outpath, path, pathlen);
    memcpy(outpath + pathlen, ENCRYPTED_SUFFIX, suffixlen);
    outpath[pathlen + suffixlen] = '\0';

     
    fout = fopen(outpath, "wb");
    if (!fout) {
        goto cleanup;
    }

    if (fwrite(nonce, 1, 12, fout) != 12) {
        goto cleanup;
    }

    if (total_out > 0) {
        if (fwrite(ciphertext, 1, (size_t)total_out, fout) != (size_t)total_out) {
            goto cleanup;
        }
    }

    if (fwrite(tag, 1, 16, fout) != 16) {
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    free(plaintext);
    free(ciphertext);
    free(outpath);

    return ret;
}