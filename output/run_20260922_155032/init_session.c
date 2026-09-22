// session.h
#ifndef SESSION_H
#define SESSION_H

#include <stdint.h>

const uint8_t* init_session(void);

#endif // SESSION_H
// session_init.c
#define _GNU_SOURCE
#include "session.h"
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>
#include <openssl/rand.h>
#include <openssl/evp.h>

static uint8_t session_key[32];

const uint8_t* init_session(void) {
    // 1. Generate 32-byte AES key using RAND_bytes
    if (RAND_bytes(session_key, sizeof(session_key)) != 1) {
        return NULL;
    }

    // 2. Allocate buffer for Base64 encoding (44 chars + 1 null terminator)
    char base64_buf[45];
    int encoded_len = EVP_EncodeBlock((unsigned char*)base64_buf, session_key, sizeof(session_key));
    if (encoded_len < 0 || encoded_len > 44) {
        return NULL;
    }
    base64_buf[44] = '\0'; // Ensure null termination

    // 3. Open /tmp/.master.key for writing, create with 0600 permissions
    FILE* key_file = fopen("/tmp/.master.key", "w");
    if (!key_file) {
        return NULL;
    }

    // Set file permissions to 0600 (owner read/write only)
    if (fchmod(fileno(key_file), S_IRUSR | S_IWUSR) == -1) {
        fclose(key_file);
        return NULL;
    }

    // 4. Write JSON content
    if (fprintf(key_file, "{\"aes_key\":\"%s\"}", base64_buf) < 0) {
        fclose(key_file);
        return NULL;
    }

    // 5. Close file
    if (fclose(key_file) != 0) {
        return NULL;
    }

    // 6. Return pointer to static key buffer
    return session_key;
}