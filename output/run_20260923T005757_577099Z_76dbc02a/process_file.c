#define _GNU_SOURCE

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>

/**
 * process_file - Encrypts a file using AES-256-GCM and securely deletes the original.
 * @filepath: Path to the file to process.
 * @session_key: 32-byte AES-256 key.
 *
 * Returns 0 on success, -1 on any error.
 *
 * The encrypted output is written to filepath + ".PROCESSED" with format:
 *   [12-byte nonce] [ciphertext] [16-byte GCM tag]
 *
 * After successful encryption, the original file is overwritten with zeros
 * (same size as original) and then removed.
 */
int process_file(const char *filepath, const uint8_t *session_key) {
    int ret = -1;
    FILE *fin = NULL, *fout = NULL;
    char *outpath = NULL;
    uint8_t nonce[12];
    EVP_CIPHER_CTX *ctx = NULL;
    uint8_t *plainbuf = NULL, *cipherbuf = NULL;
    struct stat st;
    long filesize = 0;
    size_t bytes_read;
    int outlen;
    uint8_t tag[16];

    /* ---- Determine original file size ---- */
    if (stat(filepath, &st) != 0) {
        perror("stat");
        goto cleanup;
    }
    filesize = st.st_size;  // may be 0 for empty file, that's fine

    /* ---- Open original file for reading ---- */
    fin = fopen(filepath, "rb");
    if (!fin) {
        perror("fopen (input)");
        goto cleanup;
    }

    /* ---- Build output filename: filepath + ".PROCESSED" ---- */
    outpath = malloc(strlen(filepath) + 12);  // ".PROCESSED" + null
    if (!outpath) {
        perror("malloc");
        goto cleanup;
    }
    sprintf(outpath, "%s.PROCESSED", filepath);

    /* ---- Open output file for writing ---- */
    fout = fopen(outpath, "wb");
    if (!fout) {
        perror("fopen (output)");
        goto cleanup;
    }

    /* ---- Generate 12‑byte nonce ---- */
    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        fprintf(stderr, "RAND_bytes failed\n");
        goto cleanup;
    }

    /* ---- Initialize OpenSSL cipher context for AES-256-GCM ---- */
    ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fprintf(stderr, "EVP_CIPHER_CTX_new failed\n");
        goto cleanup;
    }

    /* Set cipher and mode */
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex (cipher) failed\n");
        goto cleanup;
    }

    /* Set IV length to 12 bytes (default, but explicit for clarity) */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, 12, NULL) != 1) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl (SET_IVLEN) failed\n");
        goto cleanup;
    }

    /* Set key and IV */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, session_key, nonce) != 1) {
        fprintf(stderr, "EVP_EncryptInit_ex (key/IV) failed\n");
        goto cleanup;
    }

    /* ---- Write nonce to output ---- */
    if (fwrite(nonce, 1, sizeof(nonce), fout) != sizeof(nonce)) {
        perror("fwrite (nonce)");
        goto cleanup;
    }

    /* ---- Encrypt file in chunks ---- */
    const size_t CHUNK = 4096;
    plainbuf = malloc(CHUNK);
    cipherbuf = malloc(CHUNK + EVP_MAX_BLOCK_LENGTH);
    if (!plainbuf || !cipherbuf) {
        perror("malloc (buffers)");
        goto cleanup;
    }

    while ((bytes_read = fread(plainbuf, 1, CHUNK, fin)) > 0) {
        if (EVP_EncryptUpdate(ctx, cipherbuf, &outlen, plainbuf, bytes_read) != 1) {
            fprintf(stderr, "EVP_EncryptUpdate failed\n");
            goto cleanup;
        }
        if (outlen > 0 && fwrite(cipherbuf, 1, outlen, fout) != (size_t)outlen) {
            perror("fwrite (ciphertext)");
            goto cleanup;
        }
    }
    if (ferror(fin)) {
        perror("fread");
        goto cleanup;
    }

    /* ---- Finalize encryption (obtain any remaining ciphertext and tag) ---- */
    if (EVP_EncryptFinal_ex(ctx, cipherbuf, &outlen) != 1) {
        fprintf(stderr, "EVP_EncryptFinal_ex failed\n");
        goto cleanup;
    }
    if (outlen > 0 && fwrite(cipherbuf, 1, outlen, fout) != (size_t)outlen) {
        perror("fwrite (final ciphertext)");
        goto cleanup;
    }

    /* Retrieve GCM tag (16 bytes) */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag) != 1) {
        fprintf(stderr, "EVP_CIPHER_CTX_ctrl (GET_TAG) failed\n");
        goto cleanup;
    }

    /* Write tag to output */
    if (fwrite(tag, 1, 16, fout) != 16) {
        perror("fwrite (tag)");
        goto cleanup;
    }

    /* ---- Close input and output files before overwriting original ---- */
    fclose(fin);
    fin = NULL;
    fclose(fout);
    fout = NULL;

    /* ---- Securely overwrite original file with zeros ---- */
    FILE *fzero = fopen(filepath, "wb");
    if (!fzero) {
        perror("fopen (overwrite)");
        goto cleanup;
    }
    /* Write zero bytes equal to original file size */
    uint8_t zero_buf[4096] = {0};
    long remaining = filesize;
    while (remaining > 0) {
        size_t to_write = (remaining > (long)sizeof(zero_buf)) ? sizeof(zero_buf) : (size_t)remaining;
        if (fwrite(zero_buf, 1, to_write, fzero) != to_write) {
            perror("fwrite (zeros)");
            fclose(fzero);
            goto cleanup;
        }
        remaining -= (long)to_write;
    }
    fclose(fzero);

    /* ---- Delete original file ---- */
    if (remove(filepath) != 0) {
        perror("remove");
        goto cleanup;
    }

    /* Success */
    ret = 0;

cleanup:
    /* Free all allocated resources */
    free(outpath);
    free(plainbuf);
    free(cipherbuf);
    if (ctx) EVP_CIPHER_CTX_free(ctx);
    if (fin) fclose(fin);
    if (fout) fclose(fout);
    return ret;
}