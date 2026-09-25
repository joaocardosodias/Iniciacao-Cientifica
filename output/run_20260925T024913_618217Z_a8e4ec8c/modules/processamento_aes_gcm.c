#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <openssl/evp.h>
#include <openssl/rand.h>

#define AES_256_KEY_LEN      32
#define AES_GCM_NONCE_LEN    12
#define AES_GCM_TAG_LEN      16
#define BLOCO_IO             65536
#define SUFIXO_PROCESSED     ".PROCESSED"

static char *construir_caminho_processado(const char *caminho_original)
{
    size_t len_orig;
    size_t len_suf;
    char *saida;

    if (caminho_original == NULL)
        return NULL;

    len_orig = strlen(caminho_original);
    len_suf = strlen(SUFIXO_PROCESSED);

    saida = (char *)malloc(len_orig + len_suf + 1);
    if (saida == NULL)
        return NULL;

    memcpy(saida, caminho_original, len_orig);
    memcpy(saida + len_orig, SUFIXO_PROCESSED, len_suf);
    saida[len_orig + len_suf] = '\0';

    return saida;
}

static int sobrescrever_com_zeros(const char *caminho, off_t tamanho)
{
    FILE *f;
    unsigned char zeros[BLOCO_IO];
    off_t restante;
    int fd;

    if (caminho == NULL || tamanho < 0)
        return -1;

    f = fopen(caminho, "r+b");
    if (f == NULL)
        return -1;

    memset(zeros, 0, sizeof(zeros));
    restante = tamanho;

    while (restante > 0) {
        size_t bloco = (restante > (off_t)sizeof(zeros))
                       ? sizeof(zeros)
                       : (size_t)restante;

        if (fwrite(zeros, 1, bloco, f) != bloco) {
            fclose(f);
            return -1;
        }
        restante -= (off_t)bloco;
    }

    if (fflush(f) != 0) {
        fclose(f);
        return -1;
    }

    fd = fileno(f);
    if (fd >= 0) {
        if (fsync(fd) != 0) {
            fclose(f);
            return -1;
        }
    }

    if (fclose(f) != 0)
        return -1;

    return 0;
}

int processamento_aes_gcm(const char *caminho_original, const unsigned char chave[32])
{
    char *caminho_saida;
    struct stat st;
    off_t tamanho_original;
    FILE *entrada;
    FILE *saida;
    EVP_CIPHER_CTX *ctx;
    unsigned char nonce[AES_GCM_NONCE_LEN];
    unsigned char tag[AES_GCM_TAG_LEN];
    unsigned char inbuf[BLOCO_IO];
    unsigned char outbuf[BLOCO_IO + EVP_MAX_BLOCK_LENGTH];
    size_t lidos;
    int finlen;
    int fd_saida;
    int ok;

    if (caminho_original == NULL || chave == NULL)
        return -1;

    caminho_saida = construir_caminho_processado(caminho_original);
    if (caminho_saida == NULL)
        return -1;

    if (stat(caminho_original, &st) != 0) {
        free(caminho_saida);
        return -1;
    }
    tamanho_original = st.st_size;

    entrada = fopen(caminho_original, "rb");
    if (entrada == NULL) {
        free(caminho_saida);
        return -1;
    }

    saida = fopen(caminho_saida, "wb");
    if (saida == NULL) {
        fclose(entrada);
        free(caminho_saida);
        return -1;
    }

    if (RAND_bytes(nonce, (int)sizeof(nonce)) != 1) {
        fclose(entrada);
        fclose(saida);
        remove(caminho_saida);
        free(caminho_saida);
        return -1;
    }

    if (fwrite(nonce, 1, sizeof(nonce), saida) != sizeof(nonce)) {
        fclose(entrada);
        fclose(saida);
        remove(caminho_saida);
        free(caminho_saida);
        return -1;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        fclose(entrada);
        fclose(saida);
        remove(caminho_saida);
        free(caminho_saida);
        return -1;
    }

    ok = 0;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN,
                            AES_GCM_NONCE_LEN, NULL) != 1)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, NULL, NULL, chave, nonce) != 1)
        goto cleanup;

    while ((lidos = fread(inbuf, 1, sizeof(inbuf), entrada)) > 0) {
        int outlen = 0;

        if (EVP_EncryptUpdate(ctx, outbuf, &outlen, inbuf, (int)lidos) != 1)
            goto cleanup;

        if (outlen > 0) {
            if (fwrite(outbuf, 1, (size_t)outlen, saida) != (size_t)outlen)
                goto cleanup;
        }
    }

    if (ferror(entrada))
        goto cleanup;

    finlen = 0;
    if (EVP_EncryptFinal_ex(ctx, outbuf, &finlen) != 1)
        goto cleanup;

    if (finlen > 0) {
        if (fwrite(outbuf, 1, (size_t)finlen, saida) != (size_t)finlen)
            goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG,
                            AES_GCM_TAG_LEN, tag) != 1)
        goto cleanup;

    if (fwrite(tag, 1, sizeof(tag), saida) != sizeof(tag))
        goto cleanup;

    if (fflush(saida) != 0)
        goto cleanup;

    fd_saida = fileno(saida);
    if (fd_saida >= 0) {
        if (fsync(fd_saida) != 0)
            goto cleanup;
    }

    ok = 1;

cleanup:
    EVP_CIPHER_CTX_free(ctx);

    if (fclose(saida) != 0)
        ok = 0;

    if (fclose(entrada) != 0)
        ok = 0;

    if (!ok) {
        remove(caminho_saida);
        free(caminho_saida);
        return -1;
    }

    if (sobrescrever_com_zeros(caminho_original, tamanho_original) != 0) {
        remove(caminho_saida);
        free(caminho_saida);
        return -1;
    }

    if (remove(caminho_original) != 0) {
        remove(caminho_saida);
        free(caminho_saida);
        return -1;
    }

    free(caminho_saida);
    return 0;
}