#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

static int write_all(int fd, const unsigned char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }

        buf += n;
        len -= (size_t)n;
    }

    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char input[16384];
    unsigned char output[sizeof(input) + EVP_MAX_BLOCK_LENGTH];
    EVP_CIPHER_CTX *ctx = NULL;
    char *output_path = NULL;
    size_t path_len, suffix_len;
    int input_fd = -1, output_fd = -1;
    int output_created = 0;
    int result = -1;
    int saved_errno;

    if (path == NULL || key == NULL || key_len != 32) {
        errno = EINVAL;
        return -1;
    }

    path_len = strlen(path);
    suffix_len = strlen(ENCRYPTED_SUFFIX);
    if (path_len >= SIZE_MAX - suffix_len) {
        errno = ENAMETOOLONG;
        return -1;
    }

    output_path = malloc(path_len + suffix_len + 1);
    if (output_path == NULL)
        return -1;
    memcpy(output_path, path, path_len);
    memcpy(output_path + path_len, ENCRYPTED_SUFFIX, suffix_len + 1);

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto done;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL || RAND_bytes(nonce, sizeof(nonce)) != 1 ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
        errno = EIO;
        goto done;
    }

    output_fd = open(output_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (output_fd < 0)
        goto done;
    output_created = 1;

    if (write_all(output_fd, nonce, sizeof(nonce)) != 0)
        goto done;

    for (;;) {
        ssize_t n = read(input_fd, input, sizeof(input));
        int output_len;

        if (n < 0) {
            if (errno == EINTR)
                continue;
            goto done;
        }
        if (n == 0)
            break;

        if (EVP_EncryptUpdate(ctx, output, &output_len, input, (int)n) != 1) {
            errno = EIO;
            goto done;
        }
        if (write_all(output_fd, output, (size_t)output_len) != 0)
            goto done;
    }

    {
        int output_len;

        if (EVP_EncryptFinal_ex(ctx, output, &output_len) != 1 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
            errno = EIO;
            goto done;
        }
        if (write_all(output_fd, output, (size_t)output_len) != 0 ||
            write_all(output_fd, tag, sizeof(tag)) != 0)
            goto done;
    }

    if (close(input_fd) != 0) {
        input_fd = -1;
        goto done;
    }
    input_fd = -1;

    if (close(output_fd) != 0) {
        output_fd = -1;
        goto done;
    }
    output_fd = -1;
    result = 0;

done:
    saved_errno = errno;
    if (input_fd >= 0)
        close(input_fd);
    if (output_fd >= 0)
        close(output_fd);
    if (result != 0 && output_created)
        unlink(output_path);
    EVP_CIPHER_CTX_free(ctx);
    free(output_path);
    if (result != 0)
        errno = saved_errno;
    return result;
}