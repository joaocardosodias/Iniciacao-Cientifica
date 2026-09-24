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

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

static int write_all(FILE *file, const unsigned char *data, size_t length)
{
    while (length > 0) {
        size_t written = fwrite(data, 1, length, file);
        if (written == 0)
            return -1;
        data += written;
        length -= written;
    }
    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char input_buffer[65536];
    unsigned char output_buffer[65536 + EVP_MAX_BLOCK_LENGTH];
    EVP_CIPHER_CTX *ctx = NULL;
    FILE *input = NULL;
    FILE *output = NULL;
    char *output_path = NULL;
    int output_created = 0;
    int result = -1;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    if (asprintf(&output_path, "%s%s", path, ENCRYPTED_SUFFIX) < 0)
        return -1;

    input = fopen(path, "rb");
    if (input == NULL)
        goto cleanup;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    output = fopen(output_path, "wb");
    if (output == NULL)
        goto cleanup;
    output_created = 1;

    if (write_all(output, nonce, sizeof(nonce)) != 0)
        goto cleanup;

    for (;;) {
        size_t input_length = fread(input_buffer, 1, sizeof(input_buffer), input);
        if (input_length > 0) {
            int output_length;
            if (EVP_EncryptUpdate(ctx, output_buffer, &output_length,
                                  input_buffer, (int)input_length) != 1 ||
                write_all(output, output_buffer, (size_t)output_length) != 0)
                goto cleanup;
        }

        if (input_length < sizeof(input_buffer)) {
            if (ferror(input))
                goto cleanup;
            if (feof(input))
                break;
        }
    }

    {
        int output_length;
        if (EVP_EncryptFinal_ex(ctx, output_buffer, &output_length) != 1 ||
            write_all(output, output_buffer, (size_t)output_length) != 0 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1 ||
            write_all(output, tag, sizeof(tag)) != 0 ||
            fflush(output) != 0)
            goto cleanup;
    }

    result = 0;

cleanup:
    if (output != NULL) {
        if (fclose(output) != 0)
            result = -1;
    }
    if (input != NULL) {
        if (fclose(input) != 0)
            result = -1;
    }
    if (result != 0 && output_created)
        remove(output_path);

    EVP_CIPHER_CTX_free(ctx);
    free(output_path);
    return result;
}