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
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    const size_t max_size = (size_t)-1;
    const size_t header_len = 13;
    const size_t tag_len = 16;
    const size_t slack = EVP_MAX_BLOCK_LENGTH;
    unsigned char *input = NULL;
    unsigned char *output = NULL;
    char *final_path = NULL;
    char *temp_path = NULL;
    size_t input_len = 0;
    size_t input_cap = 0;
    size_t path_len;
    size_t suffix_len;
    size_t final_len;
    size_t temp_len;
    size_t output_len;
    size_t cipher_len = 0;
    size_t offset;
    int input_fd = -1;
    int temp_fd = -1;
    int temp_path_ready = 0;
    int result = -1;
    EVP_CIPHER_CTX *ctx = NULL;

    if (path == NULL || key == NULL || key_len != 32)
        goto cleanup;

    path_len = strlen(path);
    suffix_len = strlen(ENCRYPTED_SUFFIX);
    if (path_len > max_size - suffix_len)
        goto cleanup;
    final_len = path_len + suffix_len;
    if (final_len > max_size - 4)
        goto cleanup;
    temp_len = final_len + 4;

    final_path = malloc(final_len + 1);
    temp_path = malloc(temp_len + 1);
    if (final_path == NULL || temp_path == NULL)
        goto cleanup;

    memcpy(final_path, path, path_len);
    memcpy(final_path + path_len, ENCRYPTED_SUFFIX, suffix_len);
    final_path[final_len] = '\0';
    memcpy(temp_path, final_path, final_len);
    memcpy(temp_path + final_len, ".tmp", 5);
    temp_path_ready = 1;

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto cleanup;

    for (;;) {
        unsigned char chunk[16384];
        ssize_t n;

        do {
            n = read(input_fd, chunk, sizeof(chunk));
        } while (n < 0 && errno == EINTR);

        if (n < 0)
            goto cleanup;
        if (n == 0)
            break;

        if ((size_t)n > max_size - input_len)
            goto cleanup;
        size_t needed = input_len + (size_t)n;
        if (needed > input_cap) {
            size_t new_cap = input_cap == 0 ? sizeof(chunk) : input_cap;
            while (new_cap < needed) {
                if (new_cap > max_size / 2) {
                    new_cap = needed;
                    break;
                }
                new_cap *= 2;
            }
            unsigned char *grown = realloc(input, new_cap);
            if (grown == NULL)
                goto cleanup;
            input = grown;
            input_cap = new_cap;
        }
        memcpy(input + input_len, chunk, (size_t)n);
        input_len = needed;
    }

    if (close(input_fd) < 0) {
        input_fd = -1;
        goto cleanup;
    }
    input_fd = -1;

    if (input_len > max_size - header_len - tag_len - slack)
        goto cleanup;
    output_len = header_len + input_len + tag_len;
    output = malloc(output_len + slack);
    if (output == NULL)
        goto cleanup;

    output[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    if (RAND_bytes(output + 1, 12) != 1)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto cleanup;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, output + 1) != 1)
        goto cleanup;

    offset = 0;
    while (offset < input_len) {
        size_t remaining = input_len - offset;
        int chunk_len = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int produced = 0;

        if (EVP_EncryptUpdate(ctx, output + header_len + cipher_len, &produced,
                              input + offset, chunk_len) != 1 ||
            produced < 0 ||
            (size_t)produced > input_len - cipher_len)
            goto cleanup;
        cipher_len += (size_t)produced;
        offset += (size_t)chunk_len;
    }

    {
        int produced = 0;
        if (EVP_EncryptFinal_ex(ctx, output + header_len + cipher_len, &produced) != 1 ||
            produced < 0 ||
            (size_t)produced > input_len - cipher_len)
            goto cleanup;
        cipher_len += (size_t)produced;
    }

    if (cipher_len != input_len ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)tag_len,
                            output + header_len + input_len) != 1)
        goto cleanup;

    temp_fd = open(temp_path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    if (temp_fd < 0)
        goto cleanup;

    offset = 0;
    while (offset < output_len) {
        size_t remaining = output_len - offset;
        size_t amount = remaining > 1048576 ? 1048576 : remaining;
        ssize_t n;

        do {
            n = write(temp_fd, output + offset, amount);
        } while (n < 0 && errno == EINTR);

        if (n <= 0)
            goto cleanup;
        offset += (size_t)n;
    }

    for (;;) {
        if (fsync(temp_fd) == 0)
            break;
        if (errno != EINTR)
            goto cleanup;
    }

    if (close(temp_fd) < 0) {
        temp_fd = -1;
        goto cleanup;
    }
    temp_fd = -1;

    if (rename(temp_path, final_path) < 0)
        goto cleanup;

    result = 0;

cleanup:
    if (input_fd >= 0)
        close(input_fd);
    if (temp_fd >= 0)
        close(temp_fd);
    if (result != 0 && temp_path_ready)
        unlink(temp_path);
    EVP_CIPHER_CTX_free(ctx);
    free(output);
    free(input);
    free(temp_path);
    free(final_path);
    return result;
}