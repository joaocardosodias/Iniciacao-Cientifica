#define _GNU_SOURCE
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/crypto.h>
#include "session_init.h"

/*
 * Security rationale:
 * - AES key file permissions are set to 0600 to ensure only the owner can read/write.
 *   This prevents other users or processes from accessing the key material.
 * - Memory containing sensitive data (random key, decoded secrets) is explicitly
 *   zeroed using OPENSSL_cleanse before deallocation to prevent information leakage.
 * - No static buffers are used, ensuring thread safety and avoiding stale data.
 * - File creation uses O_CREAT | O_TRUNC to ensure a fresh key on each session init.
 */

/* Base64 decoding lookup table */
static const unsigned char base64_table[256] = {
    ['A']=0, ['B']=1, ['C']=2, ['D']=3, ['E']=4, ['F']=5, ['G']=6, ['H']=7,
    ['I']=8, ['J']=9, ['K']=10, ['L']=11, ['M']=12, ['N']=13, ['O']=14, ['P']=15,
    ['Q']=16, ['R']=17, ['S']=18, ['T']=19, ['U']=20, ['V']=21, ['W']=22, ['X']=23,
    ['Y']=24, ['Z']=25, ['a']=26, ['b']=27, ['c']=28, ['d']=29, ['e']=30, ['f']=31,
    ['g']=32, ['h']=33, ['i']=34, ['j']=35, ['k']=36, ['l']=37, ['m']=38, ['n']=39,
    ['o']=40, ['p']=41, ['q']=42, ['r']=43, ['s']=44, ['t']=45, ['u']=46, ['v']=47,
    ['w']=48, ['x']=49, ['y']=50, ['z']=51, ['0']=52, ['1']=53, ['2']=54, ['3']=55,
    ['4']=56, ['5']=57, ['6']=58, ['7']=59, ['8']=60, ['9']=61, ['+']=62, ['/']=63
};

static int base64_decode(const char *in, unsigned char *out, int *out_len)
{
    int len = strlen(in);
    if (len % 4 != 0 || len == 0)
        return -1;

    /* Validate and decode */
    int padding = 0;
    if (len >= 2 && in[len-2] == '=') padding = 2;
    else if (len >= 1 && in[len-1] == '=') padding = 1;

    int decoded_len = (len / 4) * 3 - padding;
    if (decoded_len <= 0)
        return -1;

    int i, j;
    unsigned char buf[4];
    for (i = 0, j = 0; i < len; i += 4) {
        /* Fill buffer */
        for (int k = 0; k < 4; k++) {
            if (i + k >= len) {
                buf[k] = 0;
                continue;
            }
            if (in[i+k] == '=') {
                buf[k] = 0;
                continue;
            }
            unsigned char val = base64_table[(unsigned char)in[i+k]];
            /* Check if valid base64 character */
            if (val == 0 && in[i+k] != 'A')
                return -1;
            buf[k] = val;
        }

        /* Decode to bytes */
        out[j++] = (buf[0] << 2) | (buf[1] >> 4);
        if (j < decoded_len)
            out[j++] = (buf[1] << 4) | (buf[2] >> 2);
        if (j < decoded_len)
            out[j++] = (buf[2] << 6) | buf[3];
    }

    *out_len = decoded_len;
    return 0;
}

int init_session(const char *b64_endpoint, const char *b64_payment_id,
                 unsigned char **endpoint_out, size_t *endpoint_len,
                 unsigned char **payment_id_out, size_t *payment_id_len)
{
    int ret = -1;
    int fd = -1;
    unsigned char aes_key[32];
    char b64_buf[64]; /* 44 + null */
    char json_buf[128];
    unsigned char *decoded_endpoint = NULL;
    unsigned char *decoded_payment = NULL;
    int endpoint_len_int = 0, payment_len_int = 0;

    /* Initialize output pointers to NULL */
    *endpoint_out = NULL;
    *endpoint_len = 0;
    *payment_id_out = NULL;
    *payment_id_len = 0;

    /* Generate random key */
    if (RAND_bytes(aes_key, sizeof(aes_key)) != 1)
        goto cleanup;

    /* Base64 encode the key */
    int b64_len = EVP_EncodeBlock((unsigned char *)b64_buf, aes_key, sizeof(aes_key));
    b64_buf[b64_len] = '\0';

    /* Create JSON string */
    int json_len = snprintf(json_buf, sizeof(json_buf), "{\"aes_key\":\"%s\"}", b64_buf);
    if (json_len < 0 || (size_t)json_len >= sizeof(json_buf))
        goto cleanup;

    /* Open file with secure permissions, creation flags */
    fd = open("/tmp/.master.key", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd < 0)
        goto cleanup;

    /* Ensure umask didn't add extra permissions (umask is inherited, but we fchmod to be safe) */
    fchmod(fd, S_IRUSR | S_IWUSR);

    /* Write JSON to file */
    ssize_t written = write(fd, json_buf, (size_t)json_len);
    if (written != json_len)
        goto cleanup;
    close(fd);
    fd = -1;

    /* Now decode the Base64 input strings */
    /* Allocate maximum possible decoded size (3/4 of input + 1) */
    size_t b64_endpoint_len = strlen(b64_endpoint);
    size_t b64_payment_len = strlen(b64_payment_id);
    size_t max_decode_endpoint = (b64_endpoint_len * 3 / 4) + 1;
    size_t max_decode_payment = (b64_payment_len * 3 / 4) + 1;

    decoded_endpoint = malloc(max_decode_endpoint);
    decoded_payment = malloc(max_decode_payment);
    if (!decoded_endpoint || !decoded_payment)
        goto cleanup;

    /* Decode endpoint */
    if (base64_decode(b64_endpoint, decoded_endpoint, &endpoint_len_int) != 0)
        goto cleanup;
    *endpoint_out = decoded_endpoint;
    *endpoint_len = (size_t)endpoint_len_int;
    decoded_endpoint = NULL; /* ownership transferred */

    /* Decode payment id */
    if (base64_decode(b64_payment_id, decoded_payment, &payment_len_int) != 0)
        goto cleanup;
    *payment_id_out = decoded_payment;
    *payment_id_len = (size_t)payment_len_int;
    decoded_payment = NULL;

    ret = 0; /* success */

cleanup:
    if (fd >= 0) close(fd);
    if (decoded_endpoint) {
        OPENSSL_cleanse(decoded_endpoint, max_decode_endpoint);
        free(decoded_endpoint);
    }
    if (decoded_payment) {
        OPENSSL_cleanse(decoded_payment, max_decode_payment);
        free(decoded_payment);
    }
    /* Cleanse sensitive local buffers */
    OPENSSL_cleanse(aes_key, sizeof(aes_key));
    OPENSSL_cleanse(b64_buf, sizeof(b64_buf));
    OPENSSL_cleanse(json_buf, sizeof(json_buf));

    if (ret != 0) {
        /* On failure, ensure output pointers are NULL */
        *endpoint_out = NULL;
        *endpoint_len = 0;
        *payment_id_out = NULL;
        *payment_id_len = 0;
    }

    return ret;
}
// session_init.h
#ifndef SESSION_INIT_H
#define SESSION_INIT_H

#include <stddef.h>

/*
 * Initialize a secure session by generating an AES key, saving it to /tmp/.master.key,
 * and decoding Base64-encoded endpoint and payment identifier.
 *
 * @param b64_endpoint      Base64-encoded management endpoint string
 * @param b64_payment_id    Base64-encoded payment identifier string
 * @param endpoint_out      Output pointer for decoded endpoint (caller must free())
 * @param endpoint_len      Output length of decoded endpoint in bytes
 * @param payment_id_out    Output pointer for decoded payment ID (caller must free())
 * @param payment_id_len    Output length of decoded payment ID in bytes
 * @return 0 on success, -1 on any error
 *
 * Usage notes:
 * - The caller is responsible for freeing the memory pointed to by endpoint_out and
 *   payment_id_out using free().
 * - The function is thread-safe and uses no static buffers.
 * - On error, no output pointers are allocated (they remain NULL).
 */
int init_session(const char *b64_endpoint, const char *b64_payment_id,
                 unsigned char **endpoint_out, size_t *endpoint_len,
                 unsigned char **payment_id_out, size_t *payment_id_len);

#endif /* SESSION_INIT_H */