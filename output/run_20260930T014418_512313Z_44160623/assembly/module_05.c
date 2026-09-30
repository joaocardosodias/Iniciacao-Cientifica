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

#include <errno.h>
#include <fcntl.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int write_all(int fd, const unsigned char *buffer, size_t length)
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

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    unsigned char nonce[12];
    unsigned char header[13];
    unsigned char input_buffer[65536];
    unsigned char output_buffer[65536 + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[16];
    EVP_CIPHER_CTX *ctx = NULL;
    char *final_path = NULL;
    char *temporary_path = NULL;
    size_t path_len;
    size_t suffix_len;
    size_t final_len;
    int input_fd = -1;
    int output_fd = -1;
    int temporary_created = 0;
    int result = -1;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    path_len = strlen(path);
    suffix_len = strlen(ENCRYPTED_SUFFIX);
    if (suffix_len > (size_t)-1 - path_len)
        return -1;
    final_len = path_len + suffix_len;
    if (final_len > (size_t)-1 - 5)
        return -1;

    final_path = malloc(final_len + 1);
    temporary_path = malloc(final_len + 5);
    if (final_path == NULL || temporary_path == NULL)
        goto cleanup;

    memcpy(final_path, path, path_len);
    memcpy(final_path + path_len, ENCRYPTED_SUFFIX, suffix_len);
    final_path[final_len] = '\0';
    memcpy(temporary_path, final_path, final_len);
    memcpy(temporary_path + final_len, ".tmp", 5);

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto cleanup;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    output_fd = open(temporary_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (output_fd < 0)
        goto cleanup;
    temporary_created = 1;

    header[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    memcpy(header + 1, nonce, sizeof(nonce));
    if (write_all(output_fd, header, sizeof(header)) < 0)
        goto cleanup;

    for (;;) {
        ssize_t bytes_read = read(input_fd, input_buffer, sizeof(input_buffer));
        int output_length;

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
        if (write_all(output_fd, output_buffer, (size_t)output_length) < 0)
            goto cleanup;
    }

    {
        int output_length;
        if (EVP_EncryptFinal_ex(ctx, output_buffer, &output_length) != 1)
            goto cleanup;
        if (write_all(output_fd, output_buffer, (size_t)output_length) < 0)
            goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1 ||
        write_all(output_fd, tag, sizeof(tag)) < 0)
        goto cleanup;

    if (fsync(output_fd) < 0)
        goto cleanup;
    {
        int close_result = close(output_fd);
        output_fd = -1;
        if (close_result < 0)
            goto cleanup;
    }

    {
        int close_result = close(input_fd);
        input_fd = -1;
        if (close_result < 0)
            goto cleanup;
    }

    if (rename(temporary_path, final_path) < 0)
        goto cleanup;

    temporary_created = 0;
    result = 0;

cleanup:
    if (input_fd >= 0)
        close(input_fd);
    if (output_fd >= 0)
        close(output_fd);
    if (temporary_created)
        unlink(temporary_path);
    EVP_CIPHER_CTX_free(ctx);
    free(temporary_path);
    free(final_path);
    return result;
}