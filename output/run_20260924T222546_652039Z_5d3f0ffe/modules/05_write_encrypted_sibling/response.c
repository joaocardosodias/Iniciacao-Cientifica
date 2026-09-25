#define _GNU_SOURCE
#include "config.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    FILE *in = NULL;
    FILE *out = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    char *outpath = NULL;
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char inbuf[8192];
    unsigned char outbuf[8192 + 16];
    size_t path_len;
    size_t suffix_len;
    size_t nread;
    int outlen;
    int created = 0;
    int ret = -1;

    if (!path || !key || key_len != 32)
        return -1;

    path_len = strlen(path);
    suffix_len = strlen(ENCRYPTED_SUFFIX);
    outpath = malloc(path_len + suffix_len + 1);
    if (!outpath)
        return -1;
    memcpy(outpath, path, path_len);
    memcpy(outpath + path_len, ENCRYPTED_SUFFIX, suffix_len + 1);

    if (RAND_bytes(nonce, (int)sizeof(nonce)) != 1)
        goto cleanup;

    in = fopen(path, "rb");
    if (!in)
        goto cleanup;

    out = fopen(outpath, "wb");
    if (!out)
        goto cleanup;
    created = 1;

    if (fwrite(nonce, 1, sizeof(nonce), out) != sizeof(nonce))
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (!ctx)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)sizeof(nonce), NULL) != 1)
        goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    while ((nread = fread(inbuf, 1, sizeof(inbuf), in)) > 0) {
        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)nread) != 1)
            goto cleanup;
        if (outlen > 0 && fwrite(outbuf, 1, (size_t)outlen, out) != (size_t)outlen)
            goto cleanup;
    }
    if (ferror(in))
        goto cleanup;

    if (EVP_EncryptFinal_ex(ctx, outbuf, &outlen) != 1)
        goto cleanup;
    if (outlen > 0 && fwrite(outbuf, 1, (size_t)outlen, out) != (size_t)outlen)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, (int)sizeof(tag), tag) != 1)
        goto cleanup;
    if (fwrite(tag, 1, sizeof(tag), out) != sizeof(tag))
        goto cleanup;
    if (fflush(out) != 0)
        goto cleanup;

    ret = 0;

cleanup:
    if (ctx)
        EVP_CIPHER_CTX_free(ctx);
    if (in)
        fclose(in);
    if (out)
        fclose(out);
    if (ret != 0 && created)
        remove(outpath);
    free(outpath);
    return ret;
}