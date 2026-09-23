#define _GNU_SOURCE

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <errno.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>

#include <openssl/rand.h>
#include <openssl/evp.h>
#include <openssl/err.h>

#define MASTER_KEY_PATH "/tmp/.master.key"
#define SESSION_KEY_SIZE 32

static int write_all(int fd, const void *buf, size_t len)
{
    const char *p = (const char *)buf;

    while (len > 0) {
        ssize_t n = write(fd, p, len);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }

        if (n == 0) {
            errno = EIO;
            return -1;
        }

        p += n;
        len -= (size_t)n;
    }

    return 0;
}

const uint8_t *init_session_key(void)
{
    uint8_t *key = NULL;
    char *json = NULL;
    char b64[EVP_ENCODE_LENGTH(SESSION_KEY_SIZE)];
    int fd = -1;
    int b64_len;
    size_t json_len;
    int n;

    key = (uint8_t *)malloc(SESSION_KEY_SIZE);
    if (key == NULL) {
        fprintf(stderr, "init_session_key: failed to allocate key buffer\n");
        return NULL;
    }

    if (RAND_bytes((unsigned char *)key, SESSION_KEY_SIZE) != 1) {
        fprintf(stderr, "init_session_key: RAND_bytes failed\n");
        ERR_print_errors_fp(stderr);
        goto fail;
    }

    b64_len = EVP_EncodeBlock((unsigned char *)b64,
                              (const unsigned char *)key,
                              SESSION_KEY_SIZE);
    if (b64_len <= 0) {
        fprintf(stderr, "init_session_key: EVP_EncodeBlock failed\n");
        goto fail;
    }

    json_len = 12 + (size_t)b64_len + 2;

    json = (char *)malloc(json_len + 1);
    if (json == NULL) {
        fprintf(stderr, "init_session_key: failed to allocate JSON buffer\n");
        goto fail;
    }

    n = snprintf(json, json_len + 1, "{\"aes_key\":\"%s\"}", b64);
    if (n < 0 || (size_t)n != json_len) {
        fprintf(stderr, "init_session_key: failed to build JSON payload\n");
        goto fail;
    }

    fd = open(MASTER_KEY_PATH,
              O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC | O_NOFOLLOW,
              0600);
    if (fd < 0) {
        perror("init_session_key: open " MASTER_KEY_PATH);
        goto fail;
    }

    if (fchmod(fd, 0600) != 0) {
        perror("init_session_key: fchmod " MASTER_KEY_PATH);
        goto fail;
    }

    if (write_all(fd, json, json_len) != 0) {
        perror("init_session_key: write " MASTER_KEY_PATH);
        goto fail;
    }

    if (fsync(fd) != 0) {
        perror("init_session_key: fsync " MASTER_KEY_PATH);
        goto fail;
    }

    if (close(fd) != 0) {
        perror("init_session_key: close " MASTER_KEY_PATH);
        (void)unlink(MASTER_KEY_PATH);
        fd = -1;
        goto fail;
    }
    fd = -1;

    free(json);
    return key;

fail:
    if (fd >= 0) {
        (void)close(fd);
        (void)unlink(MASTER_KEY_PATH);
    }

    free(json);
    free(key);
    return NULL;
}