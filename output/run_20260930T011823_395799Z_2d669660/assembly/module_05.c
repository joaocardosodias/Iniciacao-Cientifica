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
#include <limits.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    int result = -1;
    int input_fd = -1;
    int temp_fd = -1;
    int published = 0;
    unsigned char *plaintext = NULL;
    unsigned char *output = NULL;
    char *final_path = NULL;
    char *temp_path = NULL;
    size_t plaintext_len = 0;
    size_t plaintext_cap = 0;
    size_t output_len = 0;
    size_t output_cap = 0;
    size_t path_len;
    size_t suffix_len;
    size_t temp_len;
    size_t cipher_pos = 0;
    size_t input_pos = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *nonce;
    unsigned char *ciphertext;
    unsigned char *tag;
    int out_len;
    int final_len;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    path_len = strlen(path);
    suffix_len = strlen(ENCRYPTED_SUFFIX);
    if (path_len > SIZE_MAX - suffix_len - 1)
        return -1;

    final_path = malloc(path_len + suffix_len + 1);
    if (final_path == NULL)
        goto cleanup;
    memcpy(final_path, path, path_len);
    memcpy(final_path + path_len, ENCRYPTED_SUFFIX, suffix_len + 1);

    temp_len = path_len + suffix_len;
    if (temp_len > SIZE_MAX - sizeof(".tmp"))
        goto cleanup;
    temp_path = malloc(temp_len + sizeof(".tmp"));
    if (temp_path == NULL)
        goto cleanup;
    memcpy(temp_path, final_path, temp_len);
    memcpy(temp_path + temp_len, ".tmp", sizeof(".tmp"));

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto cleanup;

    for (;;) {
        ssize_t nread;

        if (plaintext_len == plaintext_cap) {
            size_t new_cap;

            if (plaintext_cap == 0) {
                new_cap = 8192;
            } else {
                if (plaintext_cap > SIZE_MAX / 2)
                    goto cleanup;
                new_cap = plaintext_cap * 2;
            }

            unsigned char *new_plaintext = realloc(plaintext, new_cap);
            if (new_plaintext == NULL)
                goto cleanup;
            plaintext = new_plaintext;
            plaintext_cap = new_cap;
        }

        nread = read(input_fd, plaintext + plaintext_len,
                     plaintext_cap - plaintext_len);
        if (nread < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        if (nread == 0)
            break;
        plaintext_len += (size_t)nread;
    }

    if (close(input_fd) < 0) {
        input_fd = -1;
        goto cleanup;
    }
    input_fd = -1;

    if (plaintext_len > SIZE_MAX - 1 - 12 - 16 - EVP_MAX_BLOCK_LENGTH)
        goto cleanup;
    output_len = 1 + 12 + plaintext_len + 16;
    output_cap = output_len + EVP_MAX_BLOCK_LENGTH;
    output = malloc(output_cap);
    if (output == NULL)
        goto cleanup;

    output[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    nonce = output + 1;
    ciphertext = output + 13;
    tag = ciphertext + plaintext_len;

    if (RAND_bytes(nonce, 12) != 1)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto cleanup;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1)
        goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    while (input_pos < plaintext_len) {
        size_t remaining = plaintext_len - input_pos;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;

        if (EVP_EncryptUpdate(ctx, ciphertext + cipher_pos, &out_len,
                              plaintext + input_pos, chunk) != 1)
            goto cleanup;
        if (out_len < 0 || (size_t)out_len > output_cap - 13 - cipher_pos)
            goto cleanup;
        cipher_pos += (size_t)out_len;
        input_pos += (size_t)chunk;
    }

    if (EVP_EncryptFinal_ex(ctx, ciphertext + cipher_pos, &final_len) != 1)
        goto cleanup;
    if (final_len < 0 || (size_t)final_len > output_cap - 13 - cipher_pos)
        goto cleanup;
    cipher_pos += (size_t)final_len;
    if (cipher_pos != plaintext_len)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1)
        goto cleanup;

    temp_fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (temp_fd < 0)
        goto cleanup;

    {
        size_t written = 0;

        while (written < output_len) {
            ssize_t nwritten = write(temp_fd, output + written,
                                     output_len - written);
            if (nwritten < 0) {
                if (errno == EINTR)
                    continue;
                goto cleanup;
            }
            if (nwritten == 0)
                goto cleanup;
            written += (size_t)nwritten;
        }
    }

    if (fsync(temp_fd) < 0)
        goto cleanup;

    {
        int close_result = close(temp_fd);
        temp_fd = -1;
        if (close_result < 0)
            goto cleanup;
    }

    if (rename(temp_path, final_path) < 0)
        goto cleanup;
    published = 1;
    result = 0;

cleanup:
    if (input_fd >= 0)
        close(input_fd);
    if (temp_fd >= 0)
        close(temp_fd);
    if (result != 0 && temp_path != NULL)
        unlink(temp_path);
    EVP_CIPHER_CTX_free(ctx);
    free(output);
    free(plaintext);
    free(temp_path);
    free(final_path);
    (void)published;
    return result;
}