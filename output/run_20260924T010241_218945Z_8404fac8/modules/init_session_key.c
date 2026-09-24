#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

// session_key.h content (embedded for completeness)
#ifndef SESSION_KEY_H
#define SESSION_KEY_H
#include <stdint.h>
const uint8_t* init_session_key(void);
#endif

// session_key.c implementation

const uint8_t* init_session_key(void) {
    static unsigned char key[32];
    unsigned char b64[64]; // base64 output: 44 chars + padding + null
    int b64_len;
    FILE *fp;
    const char *path = "/tmp/.master.key";

    // Generate random 32-byte session key
    if (RAND_bytes(key, sizeof(key)) != 1) {
        fprintf(stderr, "Error: RAND_bytes failed\n");
        return NULL;
    }

    // Base64 encode
    b64_len = EVP_EncodeBlock(b64, key, sizeof(key));
    if (b64_len <= 0) {
        fprintf(stderr, "Error: EVP_EncodeBlock failed\n");
        return NULL;
    }

    // Write JSON to file
    fp = fopen(path, "w");
    if (!fp) {
        perror("fopen");
        return NULL;
    }
    if (fprintf(fp, "{\"aes_key\":\"%s\"}", b64) < 0) {
        perror("fprintf");
        fclose(fp);
        return NULL;
    }
    if (fclose(fp) != 0) {
        perror("fclose");
        return NULL;
    }

    // Set permissions 0600
    if (chmod(path, S_IRUSR | S_IWUSR) != 0) {
        perror("chmod");
        return NULL;
    }

    // Return pointer to static key buffer
    return (const uint8_t*)key;
}