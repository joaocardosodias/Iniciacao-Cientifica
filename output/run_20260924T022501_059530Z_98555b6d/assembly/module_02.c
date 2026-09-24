#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SESSION_KEY_SIZE 32
#define SESSION_BASE64_SIZE 45
#define SESSION_JSON_PREFIX "{\"session_token\":\""
#define SESSION_JSON_SUFFIX "\"}"
#define SESSION_JSON_SIZE 65
#define SESSION_TOKEN_PATH "/tmp/.session.token"
#define SESSION_TEMP_TEMPLATE "/tmp/.session.token.XXXXXX"

int chave_de_sessao(uint8_t chave[SESSION_KEY_SIZE])
{
    char base64[SESSION_BASE64_SIZE];
    char json[SESSION_JSON_SIZE];
    char temp_path[] = SESSION_TEMP_TEMPLATE;
    size_t json_len;
    size_t written;
    int fd = -1;
    int temp_created = 0;
    int result = -1;
    int saved_errno = 0;
    int encoded_len;

    if (chave == NULL) {
        errno = EINVAL;
        return -1;
    }

    memset(chave, 0, SESSION_KEY_SIZE);
    memset(base64, 0, sizeof(base64));
    memset(json, 0, sizeof(json));

    if (RAND_bytes(chave, SESSION_KEY_SIZE) != 1) {
        errno = EIO;
        goto cleanup;
    }

    encoded_len = EVP_EncodeBlock((unsigned char *)base64, chave,
                                  SESSION_KEY_SIZE);
    if (encoded_len != SESSION_BASE64_SIZE - 1) {
        errno = EIO;
        goto cleanup;
    }

    memcpy(json, SESSION_JSON_PREFIX, sizeof(SESSION_JSON_PREFIX) - 1);
    memcpy(json + sizeof(SESSION_JSON_PREFIX) - 1, base64,
           (size_t)encoded_len);
    memcpy(json + sizeof(SESSION_JSON_PREFIX) - 1 + (size_t)encoded_len,
           SESSION_JSON_SUFFIX, sizeof(SESSION_JSON_SUFFIX) - 1);
    json_len = sizeof(SESSION_JSON_PREFIX) - 1 + (size_t)encoded_len +
               sizeof(SESSION_JSON_SUFFIX) - 1;

    fd = mkstemp(temp_path);
    if (fd < 0)
        goto cleanup;
    temp_created = 1;

    if (fchmod(fd, 0600) < 0)
        goto cleanup;

    written = 0;
    while (written < json_len) {
        ssize_t n = write(fd, json + written, json_len - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        if (n == 0) {
            errno = EIO;
            goto cleanup;
        }
        written += (size_t)n;
    }

    if (fsync(fd) < 0)
        goto cleanup;

    if (close(fd) < 0) {
        fd = -1;
        goto cleanup;
    }
    fd = -1;

    if (rename(temp_path, SESSION_TOKEN_PATH) < 0)
        goto cleanup;

    temp_created = 0;
    result = 0;

cleanup:
    if (result != 0) {
        saved_errno = errno ? errno : EIO;
        if (fd >= 0)
            close(fd);
        if (temp_created)
            unlink(temp_path);
        OPENSSL_cleanse(chave, SESSION_KEY_SIZE);
    }

    OPENSSL_cleanse(base64, sizeof(base64));
    OPENSSL_cleanse(json, sizeof(json));

    if (result != 0)
        errno = saved_errno;

    return result;
}