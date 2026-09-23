#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_256_KEY_SIZE 32
#define GCM_NONCE_SIZE 12
#define GCM_TAG_SIZE 16
#define BUFFER_SIZE 4096

static void wipe_memory(void *ptr, size_t len) {
    if (ptr && len > 0) {
        OPENSSL_cleanse(ptr, len);
    }
}

int apply_transform(const char *file_path, const uint8_t *key_32bytes) {
    if (!file_path || !key_32bytes) {
        fprintf(stderr, "Invalid arguments\n");
        return -1;
    }

    FILE *input_file = NULL;
    FILE *output_file = NULL;
    FILE *wipe_file = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t nonce[GCM_NONCE_SIZE];
    uint8_t tag[GCM_TAG_SIZE];
    uint8_t *in_buf = NULL;
    uint8_t *out_buf = NULL;
    uint8_t *zero_buf = NULL;
    char *output_path = NULL;
    int ret = -1;
    struct stat file_stat;
    long file_size = 0;
    unsigned char *ciphertext = NULL;
    size_t ciphertext_len = 0;
    size_t total_out_len = 0;
    int out_len = 0;
    int final_len = 0;

    memset(nonce, 0, sizeof(nonce));
    memset(tag, 0, sizeof(tag));

    if (stat(file_path, &file_stat) != 0) {
        fprintf(stderr, "stat failed for %s\n", file_path);
        goto cleanup;
    }
    file_size = file_stat.st_size;

    in_buf = (uint8_t *)malloc(BUFFER_SIZE);
    out_buf = (uint8_t *)malloc(BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
    zero_buf = (uint8_t *)malloc(BUFFER_SIZE);
    if (!in_buf || !out_buf || !zero_buf) {
        fprintf(stderr, "Memory allocation failed\n");
        goto cleanup;
    }
    memset(zero_buf, 0, BUFFER_SIZE);

    if (asprintf(&output_path, "%s.PROCESSED", file_path) == -1) {
        fprintf(stderr, "asprintf failed\n");
        output_path = NULL;
        goto cleanup;
    }

    if (RAND_bytes(nonce, GCM_NONCE_SIZE) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex (alg) failed\n");
        goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, GCM_NONCE_SIZE, NULL) != 1) {
        fprintf(stderr, "EVP_CTRL_GCM_SET_IVLEN failed\n");
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key_32bytes, nonce) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex (key/iv) failed\n");
        goto cleanup;
    }

    input_file = fopen(file_path, "rb");
    if (!input_file) {
        fprintf(stderr, "Cannot open input file %s\n", file_path);
        goto cleanup;
    }

    output_file = fopen(output_path, "wb");
    if (!output_file) {
        fprintf(stderr, "Cannot open output file %s\n", output_path);
        goto cleanup;
    }

    if (fwrite(nonce, 1, GCM_NONCE_SIZE, output_file) != GCM_NONCE_SIZE) {
        fprintf(stderr, "Failed to write nonce\n");
        goto cleanup;
    }

    ciphertext_len = 0;
    size_t bytes_read;
    while ((bytes_read = fread(in_buf, 1, BUFFER_SIZE, input_file)) > 0) {
        if (bytes_read < 0) {
            fprintf(stderr, "Read error\n");
            goto cleanup;
        }

        if (EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, (int)bytes_read) != 1) {
            fprintf(stderr, "EVP_EncryptUpdate failed\n");
            goto cleanup;
        }

        if (fwrite(out_buf, 1, out_len, output_file) != (size_t)out_len) {
            fprintf(stderr, "Failed to write ciphertext\n");
            goto cleanup;
        }
        ciphertext_len += (size_t)out_len;
    }

    if (ferror(input_file)) {
        fprintf(stderr, "Input file read error\n");
        goto cleanup;
    }

    if (EVP_EncryptFinal_ex(ctx, out_buf, &final_len) != 1) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
        goto cleanup;
    }

    if (final_len > 0) {
        if (fwrite(out_buf, 1, final_len, output_file) != (size_t)final_len) {
            fprintf(stderr, "Failed to write final block\n");
            goto cleanup;
        }
        ciphertext_len += (size_t)final_len;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, GCM_TAG_SIZE, tag) != 1) {
        fprintf(stderr, "EVP_CTRL_GCM_GET_TAG failed\n");
        goto cleanup;
    }

    if (fwrite(tag, 1, GCM_TAG_SIZE, output_file) != GCM_TAG_SIZE) {
        fprintf(stderr, "Failed to write tag\n");
        goto cleanup;
    }

    if (fflush(output_file) != 0) {
        fprintf(stderr, "fflush output failed\n");
        goto cleanup;
    }

    fclose(output_file);
    output_file = NULL;

    fclose(input_file);
    input_file = NULL;

    wipe_file = fopen(file_path, "wb");
    if (!wipe_file) {
        fprintf(stderr, "Cannot open file for wiping: %s\n", file_path);
        goto cleanup;
    }

    size_t remaining = (size_t)file_size;
    size_t write_len;
    while (remaining > 0) {
        write_len = (remaining > BUFFER_SIZE) ? BUFFER_SIZE : remaining;
        if (fwrite(zero_buf, 1, write_len, wipe_file) != write_len) {
            fprintf(stderr, "Wipe write failed\n");
            goto cleanup;
        }
        remaining -= write_len;
    }

    if (fflush(wipe_file) != 0) {
        fprintf(stderr, "fflush wipe failed\n");
        goto cleanup;
    }

    fclose(wipe_file);
    wipe_file = NULL;

    if (remove(file_path) != 0) {
        fprintf(stderr, "remove failed for %s\n", file_path);
        goto cleanup;
    }

    ret = 0;

cleanup:
    if (ctx) {
        EVP_CIPHER_CTX_free(ctx);
        ctx = NULL;
    }

    if (input_file) {
        fclose(input_file);
        input_file = NULL;
    }

    if (output_file) {
        fclose(output_file);
        output_file = NULL;
    }

    if (wipe_file) {
        fclose(wipe_file);
        wipe_file = NULL;
    }

    if (in_buf) {
        wipe_memory(in_buf, BUFFER_SIZE);
        free(in_buf);
        in_buf = NULL;
    }

    if (out_buf) {
        wipe_memory(out_buf, BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH);
        free(out_buf);
        out_buf = NULL;
    }

    if (zero_buf) {
        wipe_memory(zero_buf, BUFFER_SIZE);
        free(zero_buf);
        zero_buf = NULL;
    }

    if (output_path) {
        free(output_path);
        output_path = NULL;
    }

    wipe_memory(nonce, sizeof(nonce));
    wipe_memory(tag, sizeof(tag));

    if (ret == -1) {
        if (output_path) {
            remove(output_path);
        }
        if (ciphertext_len > 0) {
            (void)ciphertext_len;
        }
    }

    return ret;
}