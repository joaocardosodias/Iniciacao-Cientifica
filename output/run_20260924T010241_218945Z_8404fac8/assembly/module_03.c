#define _GNU_SOURCE

#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

/* Return codes */
#define SUCCESS         0
#define ERR_INVALID_ARGS -1
#define ERR_CRYPTO       -2
#define ERR_FILE_IO      -3
#define ERR_MEMORY       -4
#define ERR_RAND         -5

/* Buffer size for chunked I/O */
#define CHUNK_SIZE 4096

/* Nonce length for AES-256-GCM (96 bits) */
#define NONCE_LEN 12
/* GCM authentication tag length (128 bits) */
#define TAG_LEN 16

/* Key length must be exactly 32 bytes for AES-256 */
#define AES_256_KEY_LEN 32

/**
 * apply_transform - Securely encrypt a file using AES-256-GCM,
 *                   write the encrypted output to <file>.PROCESSED,
 *                   then securely overwrite and delete the original file.
 *
 * @file_path: Path to the file to encrypt.
 * @key:       32-byte AES-256 encryption key.
 * @key_len:   Length of the key (must be 32).
 *
 * Return: 0 on success, negative error code on failure.
 */
int apply_transform(const char* file_path, const uint8_t* key, size_t key_len)
{
    /* --- 1. Input validation --- */
    if (!file_path || !key || key_len != AES_256_KEY_LEN) {
        return ERR_INVALID_ARGS;
    }

    /* Verify the input file exists and is not a directory */
    struct stat path_stat;
    if (stat(file_path, &path_stat) != 0) {
        return ERR_FILE_IO; /* errno will be set */
    }
    if (!S_ISREG(path_stat.st_mode)) {
        return ERR_FILE_IO; /* Not a regular file */
    }

    /* --- 2. Open the original file for reading --- */
    FILE *fin = fopen(file_path, "rb");
    if (!fin) {
        return ERR_FILE_IO;
    }

    /* Determine file size for zero overwrite */
    long file_size;
    if (fseek(fin, 0, SEEK_END) != 0) {
        fclose(fin);
        return ERR_FILE_IO;
    }
    file_size = ftell(fin);
    if (fseek(fin, 0, SEEK_SET) != 0) {
        fclose(fin);
        return ERR_FILE_IO;
    }

    /* --- 3. Generate a random 12-byte nonce --- */
    uint8_t nonce[NONCE_LEN];
    if (RAND_bytes(nonce, NONCE_LEN) != 1) {
        fclose(fin);
        return ERR_RAND;
    }

    /* --- 4. Set up AES-256-GCM encryption --- */
    EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    if (!ctx) {
        fclose(fin);
        return ERR_MEMORY;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        return ERR_CRYPTO;
    }

    /* Set key and IV (nonce) length */
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        return ERR_CRYPTO;
    }

    /* Provide key and nonce */
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        return ERR_CRYPTO;
    }

    /* --- 5. Create the output file --- */
    size_t path_len = strlen(file_path);
    char *out_path = malloc(path_len + sizeof(".PROCESSED")); /* includes null terminator */
    if (!out_path) {
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        return ERR_MEMORY;
    }
    memcpy(out_path, file_path, path_len);
    memcpy(out_path + path_len, ".PROCESSED", sizeof(".PROCESSED")); /* copies null */

    FILE *fout = fopen(out_path, "wb");
    if (!fout) {
        free(out_path);
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        return ERR_FILE_IO;
    }

    /* Write nonce first */
    if (fwrite(nonce, 1, NONCE_LEN, fout) != NONCE_LEN) {
        goto cleanup_error;
    }

    /* --- 6. Encrypt file contents in chunks --- */
    uint8_t in_buf[CHUNK_SIZE];
    uint8_t out_buf[CHUNK_SIZE + EVP_MAX_BLOCK_LENGTH];
    int out_len = 0;
    size_t bytes_read;

    while ((bytes_read = fread(in_buf, 1, CHUNK_SIZE, fin)) > 0) {
        if (EVP_EncryptUpdate(ctx, out_buf, &out_len, in_buf, (int)bytes_read) != 1) {
            goto cleanup_error;
        }
        if (fwrite(out_buf, 1, out_len, fout) != (size_t)out_len) {
            goto cleanup_error;
        }
    }
    if (ferror(fin)) {
        goto cleanup_error;
    }

    /* --- 7. Finalize encryption and get tag --- */
    if (EVP_EncryptFinal_ex(ctx, out_buf, &out_len) != 1) {
        goto cleanup_error;
    }
    if (fwrite(out_buf, 1, out_len, fout) != (size_t)out_len) {
        goto cleanup_error;
    }

    uint8_t tag[TAG_LEN];
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1) {
        goto cleanup_error;
    }
    if (fwrite(tag, 1, TAG_LEN, fout) != TAG_LEN) {
        goto cleanup_error;
    }

    /* --- 8. Flush and close output file --- */
    if (fflush(fout) != 0) {
        goto cleanup_error;
    }
    fclose(fout);
    fout = NULL;

    /* --- 9. Securely overwrite the original file with zeros --- */
    FILE *fzero = fopen(file_path, "wb");
    if (!fzero) {
        /* Cannot overwrite; remove the output file to leave no partial state */
        remove(out_path);
        free(out_path);
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        return ERR_FILE_IO;
    }

    /* We already have the file size; write zeros in chunks */
    long remaining = file_size;
    uint8_t zero_buf[CHUNK_SIZE];
    memset(zero_buf, 0, CHUNK_SIZE);
    while (remaining > 0) {
        size_t write_size = (remaining > CHUNK_SIZE) ? CHUNK_SIZE : (size_t)remaining;
        if (fwrite(zero_buf, 1, write_size, fzero) != write_size) {
            fclose(fzero);
            /* Do not delete original because overwrite failed */
            remove(out_path);
            free(out_path);
            EVP_CIPHER_CTX_free(ctx);
            fclose(fin);
            return ERR_FILE_IO;
        }
        remaining -= (long)write_size;
    }
    if (fflush(fzero) != 0) {
        fclose(fzero);
        remove(out_path);
        free(out_path);
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        return ERR_FILE_IO;
    }
    fclose(fzero);

    /* --- 10. Delete the original file --- */
    if (remove(file_path) != 0) {
        /* Failure to delete is not critical but we report error */
        free(out_path);
        EVP_CIPHER_CTX_free(ctx);
        fclose(fin);
        return ERR_FILE_IO;
    }

    /* --- 11. Cleanup and return success --- */
    /* Zeroize the nonce (key is provided by caller, we do not own it) */
    OPENSSL_cleanse(nonce, NONCE_LEN);
    EVP_CIPHER_CTX_free(ctx);
    fclose(fin);
    free(out_path);
    return SUCCESS;

cleanup_error:
    /* Failure path: close files, remove any partial output, free memory */
    if (fout) {
        fclose(fout);
    }
    if (out_path) {
        /* Remove the incomplete output file */
        remove(out_path);
    }
    free(out_path);
    EVP_CIPHER_CTX_free(ctx);
    fclose(fin);
    return ERR_CRYPTO; /* Generic error, but caller can inspect errno */
}