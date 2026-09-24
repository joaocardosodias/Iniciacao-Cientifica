#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

enum file_processing_status {
    FILE_PROCESSING_SUCCESS = 0,
    FILE_PROCESSING_INVALID_ARGUMENT = 1,
    FILE_PROCESSING_INPUT_ERROR = 2,
    FILE_PROCESSING_OUTPUT_ERROR = 3,
    FILE_PROCESSING_CRYPTO_ERROR = 4,
    FILE_PROCESSING_MEMORY_ERROR = 5
};

#define FILE_PROCESSING_NONCE_SIZE 12
#define FILE_PROCESSING_TAG_SIZE 16
#define FILE_PROCESSING_BUFFER_SIZE 65536
#define FILE_PROCESSING_SUFFIX ".PROCESSED"
#define FILE_PROCESSING_TEMP_SUFFIX ".tmp.XXXXXX"

int file_processing_utility(
    const char *input_path,
    const char *output_path,
    const unsigned char key[32])
{
    FILE *input = NULL;
    FILE *output = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    char *temporary_path = NULL;
    unsigned char nonce[FILE_PROCESSING_NONCE_SIZE];
    unsigned char input_buffer[FILE_PROCESSING_BUFFER_SIZE];
    unsigned char output_buffer[FILE_PROCESSING_BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[FILE_PROCESSING_TAG_SIZE];
    struct stat input_stat;
    struct stat output_stat;
    size_t path_length;
    size_t suffix_length = sizeof(FILE_PROCESSING_SUFFIX) - 1;
    size_t temporary_suffix_length = sizeof(FILE_PROCESSING_TEMP_SUFFIX);
    size_t bytes_read;
    int temporary_fd = -1;
    int output_length = 0;
    int status = FILE_PROCESSING_SUCCESS;

    if (input_path == NULL || output_path == NULL || key == NULL ||
        input_path[0] == '\0' || output_path[0] == '\0') {
        return FILE_PROCESSING_INVALID_ARGUMENT;
    }

    path_length = strlen(output_path);
    if (path_length < suffix_length ||
        memcmp(output_path + path_length - suffix_length,
               FILE_PROCESSING_SUFFIX, suffix_length) != 0) {
        return FILE_PROCESSING_INVALID_ARGUMENT;
    }
    if (path_length > SIZE_MAX - temporary_suffix_length) {
        return FILE_PROCESSING_INVALID_ARGUMENT;
    }

    input = fopen(input_path, "rb");
    if (input == NULL) {
        return FILE_PROCESSING_INPUT_ERROR;
    }

    if (fstat(fileno(input), &input_stat) != 0) {
        status = FILE_PROCESSING_INPUT_ERROR;
        goto cleanup;
    }

    if (stat(output_path, &output_stat) == 0) {
        if (input_stat.st_dev == output_stat.st_dev &&
            input_stat.st_ino == output_stat.st_ino) {
            status = FILE_PROCESSING_INVALID_ARGUMENT;
            goto cleanup;
        }
    } else if (errno != ENOENT) {
        status = FILE_PROCESSING_OUTPUT_ERROR;
        goto cleanup;
    }

    temporary_path = malloc(path_length + temporary_suffix_length);
    if (temporary_path == NULL) {
        status = FILE_PROCESSING_MEMORY_ERROR;
        goto cleanup;
    }
    memcpy(temporary_path, output_path, path_length);
    memcpy(temporary_path + path_length, FILE_PROCESSING_TEMP_SUFFIX,
           temporary_suffix_length);

    temporary_fd = mkstemp(temporary_path);
    if (temporary_fd < 0) {
        status = FILE_PROCESSING_OUTPUT_ERROR;
        goto cleanup;
    }

    output = fdopen(temporary_fd, "wb");
    if (output == NULL) {
        status = FILE_PROCESSING_OUTPUT_ERROR;
        goto cleanup;
    }
    temporary_fd = -1;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        status = FILE_PROCESSING_CRYPTO_ERROR;
        goto cleanup;
    }

    if (fwrite(nonce, 1, sizeof(nonce), output) != sizeof(nonce)) {
        status = FILE_PROCESSING_OUTPUT_ERROR;
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        status = FILE_PROCESSING_MEMORY_ERROR;
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            (int)sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        status = FILE_PROCESSING_CRYPTO_ERROR;
        goto cleanup;
    }

    for (;;) {
        bytes_read = fread(input_buffer, 1, sizeof(input_buffer), input);
        if (bytes_read > 0) {
            if (EVP_EncryptUpdate(ctx, output_buffer, &output_length,
                                  input_buffer, (int)bytes_read) != 1) {
                status = FILE_PROCESSING_CRYPTO_ERROR;
                goto cleanup;
            }
            if (output_length < 0 ||
                fwrite(output_buffer, 1, (size_t)output_length, output) !=
                    (size_t)output_length) {
                status = FILE_PROCESSING_OUTPUT_ERROR;
                goto cleanup;
            }
        }

        if (bytes_read < sizeof(input_buffer)) {
            if (ferror(input)) {
                status = FILE_PROCESSING_INPUT_ERROR;
                goto cleanup;
            }
            if (feof(input)) {
                break;
            }
        }
    }

    if (EVP_EncryptFinal_ex(ctx, output_buffer, &output_length) != 1) {
        status = FILE_PROCESSING_CRYPTO_ERROR;
        goto cleanup;
    }
    if (output_length < 0 ||
        fwrite(output_buffer, 1, (size_t)output_length, output) !=
            (size_t)output_length) {
        status = FILE_PROCESSING_OUTPUT_ERROR;
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            (int)sizeof(tag), tag) != 1) {
        status = FILE_PROCESSING_CRYPTO_ERROR;
        goto cleanup;
    }
    if (fwrite(tag, 1, sizeof(tag), output) != sizeof(tag)) {
        status = FILE_PROCESSING_OUTPUT_ERROR;
        goto cleanup;
    }

    if (fclose(input) != 0) {
        input = NULL;
        status = FILE_PROCESSING_INPUT_ERROR;
        goto cleanup;
    }
    input = NULL;

    if (fflush(output) != 0 || fsync(fileno(output)) != 0) {
        status = FILE_PROCESSING_OUTPUT_ERROR;
        goto cleanup;
    }
    if (fclose(output) != 0) {
        output = NULL;
        status = FILE_PROCESSING_OUTPUT_ERROR;
        goto cleanup;
    }
    output = NULL;

    if (stat(output_path, &output_stat) == 0) {
        if (input_stat.st_dev == output_stat.st_dev &&
            input_stat.st_ino == output_stat.st_ino) {
            status = FILE_PROCESSING_INVALID_ARGUMENT;
            goto cleanup;
        }
    } else if (errno != ENOENT) {
        status = FILE_PROCESSING_OUTPUT_ERROR;
        goto cleanup;
    }

    if (rename(temporary_path, output_path) != 0) {
        status = FILE_PROCESSING_OUTPUT_ERROR;
        goto cleanup;
    }

cleanup:
    if (input != NULL) {
        if (fclose(input) != 0 && status == FILE_PROCESSING_SUCCESS) {
            status = FILE_PROCESSING_INPUT_ERROR;
        }
    }
    if (output != NULL) {
        if (fclose(output) != 0 && status == FILE_PROCESSING_SUCCESS) {
            status = FILE_PROCESSING_OUTPUT_ERROR;
        }
    }
    if (temporary_fd >= 0) {
        if (close(temporary_fd) != 0 && status == FILE_PROCESSING_SUCCESS) {
            status = FILE_PROCESSING_OUTPUT_ERROR;
        }
    }
    if (status != FILE_PROCESSING_SUCCESS && temporary_path != NULL) {
        (void)unlink(temporary_path);
    }

    EVP_CIPHER_CTX_free(ctx);
    OPENSSL_cleanse(nonce, sizeof(nonce));
    OPENSSL_cleanse(input_buffer, sizeof(input_buffer));
    OPENSSL_cleanse(output_buffer, sizeof(output_buffer));
    OPENSSL_cleanse(tag, sizeof(tag));
    free(temporary_path);

    return status;
}