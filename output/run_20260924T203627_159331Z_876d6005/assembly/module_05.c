#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int
write_all(int fd, const unsigned char *buffer, size_t length)
{
    while (length > 0) {
        ssize_t written = write(fd, buffer, length);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0)
            return -1;

        buffer += (size_t)written;
        length -= (size_t)written;
    }

    return 0;
}

int
write_encrypted_sibling(const char *path, const unsigned char *key,
                        size_t key_len)
{
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char input_buffer[65536];
    unsigned char output_buffer[65536 + EVP_MAX_BLOCK_LENGTH];
    EVP_CIPHER_CTX *ctx = NULL;
    char *output_path = NULL;
    int input_fd = -1;
    int output_fd = -1;
    int output_created = 0;
    int output_modified = 0;
    int success = 0;
    struct stat input_stat;
    struct stat output_stat;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    if (asprintf(&output_path, "%s%s", path, ENCRYPTED_SUFFIX) < 0)
        return -1;

    if (strcmp(path, output_path) == 0)
        goto cleanup;

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto cleanup;

    if (fstat(input_fd, &input_stat) < 0)
        goto cleanup;

    output_fd = open(output_path,
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0666);
    if (output_fd >= 0) {
        output_created = 1;
    } else if (errno == EEXIST) {
        output_fd = open(output_path, O_WRONLY | O_CLOEXEC);
        if (output_fd < 0)
            goto cleanup;
    } else {
        goto cleanup;
    }

    if (fstat(output_fd, &output_stat) < 0)
        goto cleanup;

    if (input_stat.st_dev == output_stat.st_dev &&
        input_stat.st_ino == output_stat.st_ino) {
        output_created = 0;
        goto cleanup;
    }

    if (ftruncate(output_fd, 0) < 0)
        goto cleanup;
    output_modified = 1;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    if (write_all(output_fd, nonce, sizeof(nonce)) < 0)
        goto cleanup;

    for (;;) {
        ssize_t bytes_read = read(input_fd, input_buffer, sizeof(input_buffer));
        int output_length = 0;

        if (bytes_read < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        if (bytes_read == 0)
            break;

        if (EVP_EncryptUpdate(ctx, output_buffer, &output_length, input_buffer,
                              (int)bytes_read) != 1)
            goto cleanup;

        if (output_length > 0 &&
            write_all(output_fd, output_buffer, (size_t)output_length) < 0)
            goto cleanup;
    }

    {
        int output_length = 0;

        if (EVP_EncryptFinal_ex(ctx, output_buffer, &output_length) != 1)
            goto cleanup;

        if (output_length > 0 &&
            write_all(output_fd, output_buffer, (size_t)output_length) < 0)
            goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
        goto cleanup;

    if (write_all(output_fd, tag, sizeof(tag)) < 0)
        goto cleanup;

    if (close(input_fd) < 0) {
        input_fd = -1;
        goto cleanup;
    }
    input_fd = -1;

    if (close(output_fd) < 0) {
        output_fd = -1;
        goto cleanup;
    }
    output_fd = -1;
    success = 1;

cleanup:
    if (input_fd >= 0)
        (void)close(input_fd);
    if (output_fd >= 0)
        (void)close(output_fd);
    if (!success && (output_created || output_modified))
        (void)unlink(output_path);
    EVP_CIPHER_CTX_free(ctx);
    free(output_path);

    return success ? 0 : -1;
}