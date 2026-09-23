#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

/*
 * init_session - Generate a cryptographically secure 32-byte AES-256 session key,
 *                base64-encode it, and store the JSON {"aes_key":"<base64>"} to
 *                /tmp/.master.key with permissions 0600.
 *
 * Returns a pointer to a dynamically allocated buffer containing the raw 32-byte key.
 * The caller is responsible for calling free() on the returned pointer.
 * On any failure, returns NULL and prints an error message to stderr.
 */
const uint8_t* init_session(void)
{
    uint8_t *raw_key = NULL;
    char b64[64];                 /* Base64 of 32 bytes fits in 45 characters */
    char json[128];               /* JSON object fits within 128 bytes */
    int fd = -1;
    FILE *fp = NULL;
    size_t b64_len;
    int written;

    /* Step 1: Allocate buffer for raw key */
    raw_key = malloc(32);
    if (!raw_key) {
        fprintf(stderr, "init_session: malloc failed\n");
        return NULL;
    }

    /* Step 2: Generate 32 cryptographically secure random bytes */
    if (RAND_bytes(raw_key, 32) != 1) {
        fprintf(stderr, "init_session: RAND_bytes failed\n");
        free(raw_key);
        return NULL;
    }

    /* Step 3: Base64-encode the key */
    b64_len = EVP_EncodeBlock((unsigned char*)b64, raw_key, 32);
    b64[b64_len] = '\0';   /* EVP_EncodeBlock already null-terminates, but be safe */

    /* Step 4: Build JSON string */
    snprintf(json, sizeof(json), "{\"aes_key\":\"%s\"}", b64);

    /* Step 5: Open /tmp/.master.key with 0600 permissions (owner rw only) */
    fd = open("/tmp/.master.key", O_WRONLY | O_CREAT | O_TRUNC, S_IRUSR | S_IWUSR);
    if (fd == -1) {
        fprintf(stderr, "init_session: open failed: /tmp/.master.key\n");
        free(raw_key);
        return NULL;
    }

    /* Step 6: Convert fd to FILE* for easier writing */
    fp = fdopen(fd, "w");
    if (!fp) {
        fprintf(stderr, "init_session: fdopen failed\n");
        close(fd);
        free(raw_key);
        return NULL;
    }

    /* Step 7: Write JSON to file */
    written = fprintf(fp, "%s", json);
    if (written < 0 || (size_t)written != strlen(json)) {
        fprintf(stderr, "init_session: fprintf failed\n");
        fclose(fp);
        free(raw_key);
        return NULL;
    }

    /* Step 8: Close file (also closes underlying fd) */
    if (fclose(fp) != 0) {
        fprintf(stderr, "init_session: fclose failed\n");
        free(raw_key);
        return NULL;
    }

    /* Success: return pointer to the allocated raw key */
    return raw_key;
}