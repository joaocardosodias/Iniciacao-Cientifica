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

static int safe_write(int fd, const void *buf, size_t count)
{
    const unsigned char *ptr = buf;
    while (count) {
        ssize_t written = write(fd, ptr, count);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        ptr += written;
        count -= written;
    }
    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    int ret = -1;
    int src_fd = -1;
    int tmp_fd = -1;
    struct stat st;
    unsigned char *plaintext = NULL;
    unsigned char *ciphertext = NULL;
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char version = ENCRYPTED_FORMAT_VERSION;
    char *tmp_path = NULL;
    char *final_path = NULL;

    if (!path || !key || key_len != 32) {
        errno = EINVAL;
        return -1;
    }

    src_fd = open(path, O_RDONLY);
    if (src_fd < 0)
        goto cleanup;

    if (fstat(src_fd, &st) < 0)
        goto cleanup;

    if (st.st_size > 0) {
        plaintext = malloc(st.st_size);
        if (!plaintext)
            goto cleanup;
        size_t to_read = st.st_size;
        unsigned char *p = plaintext;
        while (to_read) {
            ssize_t r = read(src_fd, p, to_read);
            if (r < 0) {
                if (errno == EINTR)
                    continue;
                goto cleanup;
            }
            if (r == 0)
                break;
            p += r;
            to_read -= r;
        }
        if (to_read != 0)
            goto cleanup;
    }

    ciphertext = malloc(st.st_size);
    if (!ciphertext)
        goto cleanup;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto cleanup;

    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto ctx_cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1)
        goto ctx_cleanup;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto ctx_cleanup;

    int outlen = 0;
    if (st.st_size > 0) {
        if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, st.st_size) != 1)
            goto ctx_cleanup;
    }
    int ciphertext_len = outlen;

    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &outlen) != 1)
        goto ctx_cleanup;
    ciphertext_len += outlen;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
        goto ctx_cleanup;

     
    {
        size_t path_len = strlen(path);
        size_t suffix_len = strlen(ENCRYPTED_SUFFIX);
        tmp_path = malloc(path_len + suffix_len + 5);    
        final_path = malloc(path_len + suffix_len + 1);
        if (!tmp_path || !final_path)
            goto ctx_cleanup;
        sprintf(tmp_path, "%s%s.tmp", path, ENCRYPTED_SUFFIX);
        sprintf(final_path, "%s%s", path, ENCRYPTED_SUFFIX);
    }

    tmp_fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL, 0600);
    if (tmp_fd < 0)
        goto ctx_cleanup;

     
    if (safe_write(tmp_fd, &version, 1) < 0)
        goto ctx_cleanup;
    if (safe_write(tmp_fd, nonce, sizeof(nonce)) < 0)
        goto ctx_cleanup;
    if (ciphertext_len > 0 && safe_write(tmp_fd, ciphertext, ciphertext_len) < 0)
        goto ctx_cleanup;
    if (safe_write(tmp_fd, tag, sizeof(tag)) < 0)
        goto ctx_cleanup;

    if (fsync(tmp_fd) < 0)
        goto ctx_cleanup;

    if (close(tmp_fd) < 0)
        tmp_fd = -1, goto ctx_cleanup;
    tmp_fd = -1;

    if (rename(tmp_path, final_path) < 0)
        goto ctx_cleanup;

    ret = 0;

ctx_cleanup:
    EVP_CIPHER_CTX_free(ctx);
cleanup:
    if (src_fd >= 0)
        close(src_fd);
    if (tmp_fd >= 0) {
        close(tmp_fd);
        unlink(tmp_path);
    }
    if (tmp_path) {
        if (ret != 0)
            unlink(tmp_path);
        free(tmp_path);
    }
    free(final_path);
    free(plaintext);
    free(ciphertext);
    return ret;
}