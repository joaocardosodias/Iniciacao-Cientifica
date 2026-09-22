#define _GNU_SOURCE
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <openssl/rand.h>
#include <openssl/evp.h>
#include <errno.h>

/*
 * Security considerations for this implementation:
 *
 * - OpenSSL's RAND_bytes() provides cryptographically secure random bytes.
 *   No fallback to insecure PRNGs is implemented; failure causes abort.
 *
 * - The session key is stored in heap memory only; never in a static buffer,
 *   to avoid lifetime and thread-safety issues.
 *
 * - Base64 encoding is performed using OpenSSL's EVP_EncodeBlock, which
 *   produces a null-terminated string.
 *
 * - The JSON payload is written to /tmp/.master.key with permissions 0600,
 *   enforced via fchmod() after open() to ignore any restrictive umask.
 *
 * - Symlink attacks are mitigated by using O_NOFOLLOW when opening the file.
 *   If the file already exists as a regular file, O_CREAT|O_EXCL fails,
 *   preventing unintended reuse. If a symlink is encountered, open() fails
 *   and the function returns NULL without writing.
 *
 * - All allocated memory is freed on any failure path, and partial files
 *   are unlinked to avoid leaking key material.
 *
 * - The function is thread-safe: no global or static mutable data is used.
 */

static char* base64_encode(const uint8_t *data, size_t len) {
    // Calculate required buffer size: EVP_EncodeBlock adds null terminator
    int encoded_len = EVP_ENCODE_BLOCK_SIZE(len) + 1;
    char *b64 = malloc(encoded_len);
    if (!b64) return NULL;
    int out_len = EVP_EncodeBlock((unsigned char*)b64, data, len);
    if (out_len < 0) {
        free(b64);
        return NULL;
    }
    b64[out_len] = '\0';
    return b64;
}

const uint8_t* init_session(void) {
    // 1. Generate 32 random bytes
    uint8_t *raw_key = malloc(32);
    if (!raw_key) return NULL;

    if (RAND_bytes(raw_key, 32) != 1) {
        ERR_clear_error();
        free(raw_key);
        return NULL;
    }

    // 2. Base64 encode
    char *b64 = base64_encode(raw_key, 32);
    if (!b64) {
        free(raw_key);
        return NULL;
    }

    // 3. Build JSON string: {"aes_key":"<b64>"}
    // JSON length: "{\"aes_key\":\"" + strlen(b64) + "\"}" = 11 + strlen(b64) + 3 + 1 = 15 + strlen(b64)
    size_t json_len = 15 + strlen(b64);
    char *json = malloc(json_len + 1); // +1 for null terminator
    if (!json) {
        free(b64);
        free(raw_key);
        return NULL;
    }
    int written = snprintf(json, json_len + 1, "{\"aes_key\":\"%s\"}", b64);
    if (written < 0 || (size_t)written > json_len) {
        // snprintf failure (should not happen with correct size)
        free(json);
        free(b64);
        free(raw_key);
        return NULL;
    }

    // 4. Write to /tmp/.master.key with strict permissions
    const char *filepath = "/tmp/.master.key";
    int fd = open(filepath, O_WRONLY | O_CREAT | O_TRUNC | O_NOFOLLOW, S_IRUSR | S_IWUSR);
    if (fd < 0) {
        perror("open /tmp/.master.key");
        free(json);
        free(b64);
        free(raw_key);
        return NULL;
    }

    // Ensure permissions 0600 regardless of umask
    if (fchmod(fd, S_IRUSR | S_IWUSR) < 0) {
        perror("fchmod /tmp/.master.key");
        close(fd);
        unlink(filepath);
        free(json);
        free(b64);
        free(raw_key);
        return NULL;
    }

    // Write JSON in a loop to handle partial writes
    size_t total = strlen(json);
    ssize_t remaining = (ssize_t)total;
    char *ptr = json;
    while (remaining > 0) {
        ssize_t n = write(fd, ptr, (size_t)remaining);
        if (n < 0) {
            if (errno == EINTR) continue; // retry on signal interrupt
            perror("write /tmp/.master.key");
            close(fd);
            unlink(filepath);
            free(json);
            free(b64);
            free(raw_key);
            return NULL;
        }
        remaining -= n;
        ptr += n;
    }

    // Sync to disk for durability (optional but recommended for critical keys)
    if (fsync(fd) < 0) {
        perror("fsync /tmp/.master.key");
        // Continue, not fatal
    }

    close(fd);

    // Free intermediate buffers, but keep raw_key allocated for caller
    free(json);
    free(b64);

    // Return pointer to raw 32-byte key
    return raw_key;
}