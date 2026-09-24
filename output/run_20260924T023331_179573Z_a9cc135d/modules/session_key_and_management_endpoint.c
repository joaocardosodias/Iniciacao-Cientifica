#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <openssl/crypto.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

#define SESSION_KEY_LENGTH 32
#define SESSION_KEY_BASE64_LENGTH 44
#define SESSION_TOKEN_PATH "/tmp/.session.token"
#define SESSION_TOKEN_TEMP_TEMPLATE "/tmp/.session.token.XXXXXX"

static const char session_management_endpoint[] = "10.254.19.73";
static const char session_token_prefix[] = "{\"aes_key\":\"";
static const char session_token_suffix[] = "\"}";

int
session_key_and_management_endpoint(const uint8_t **session_key_out,
                                   const char **management_endpoint_out)
{
    uint8_t *key;
    const uint8_t *immutable_key;
    unsigned char encoded[SESSION_KEY_BASE64_LENGTH + 1];
    char json[sizeof(session_token_prefix) - 1 +
              SESSION_KEY_BASE64_LENGTH +
              sizeof(session_token_suffix)];
    char temporary_path[] = SESSION_TOKEN_TEMP_TEMPLATE;
    size_t json_length;
    size_t written;
    size_t offset;
    int encoded_length;
    int fd;
    int temp_exists = 0;
    int saved_errno;
    struct stat st;

    if (session_key_out == NULL || management_endpoint_out == NULL) {
        errno = EINVAL;
        return -1;
    }

    *session_key_out = NULL;
    *management_endpoint_out = NULL;

    key = malloc(SESSION_KEY_LENGTH);
    if (key == NULL)
        return -1;

    if (RAND_bytes(key, SESSION_KEY_LENGTH) != 1) {
        OPENSSL_cleanse(key, SESSION_KEY_LENGTH);
        free(key);
        errno = EIO;
        return -1;
    }

    immutable_key = key;
    encoded_length = EVP_EncodeBlock(encoded, immutable_key, SESSION_KEY_LENGTH);
    if (encoded_length <= 0 ||
        encoded_length > SESSION_KEY_BASE64_LENGTH) {
        OPENSSL_cleanse(key, SESSION_KEY_LENGTH);
        free(key);
        errno = EIO;
        return -1;
    }
    encoded[encoded_length] = '\0';

    if (encoded_length == 0) {
        OPENSSL_cleanse(key, SESSION_KEY_LENGTH);
        free(key);
        errno = EIO;
        return -1;
    }

    offset = 0;
    memcpy(json + offset, session_token_prefix,
           sizeof(session_token_prefix) - 1);
    offset += sizeof(session_token_prefix) - 1;
    memcpy(json + offset, encoded, (size_t)encoded_length);
    offset += (size_t)encoded_length;
    memcpy(json + offset, session_token_suffix,
           sizeof(session_token_suffix) - 1);
    offset += sizeof(session_token_suffix) - 1;
    json_length = offset;

    fd = mkstemp(temporary_path);
    if (fd < 0) {
        saved_errno = errno;
        OPENSSL_cleanse(key, SESSION_KEY_LENGTH);
        free(key);
        errno = saved_errno;
        return -1;
    }
    temp_exists = 1;

    if (fchmod(fd, S_IRUSR | S_IWUSR) < 0 ||
        fstat(fd, &st) < 0 ||
        (st.st_mode & 0777) != (S_IRUSR | S_IWUSR)) {
        saved_errno = errno != 0 ? errno : EACCES;
        close(fd);
        unlink(temporary_path);
        OPENSSL_cleanse(key, SESSION_KEY_LENGTH);
        free(key);
        errno = saved_errno;
        return -1;
    }

    written = 0;
    while (written < json_length) {
        ssize_t n = write(fd, json + written, json_length - written);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            saved_errno = errno;
            close(fd);
            unlink(temporary_path);
            OPENSSL_cleanse(key, SESSION_KEY_LENGTH);
            free(key);
            errno = saved_errno;
            return -1;
        }
        if (n == 0) {
            close(fd);
            unlink(temporary_path);
            OPENSSL_cleanse(key, SESSION_KEY_LENGTH);
            free(key);
            errno = EIO;
            return -1;
        }
        written += (size_t)n;
    }

    if (fsync(fd) < 0) {
        saved_errno = errno;
        close(fd);
        unlink(temporary_path);
        OPENSSL_cleanse(key, SESSION_KEY_LENGTH);
        free(key);
        errno = saved_errno;
        return -1;
    }

    if (close(fd) < 0) {
        saved_errno = errno;
        unlink(temporary_path);
        OPENSSL_cleanse(key, SESSION_KEY_LENGTH);
        free(key);
        errno = saved_errno;
        return -1;
    }

    if (rename(temporary_path, SESSION_TOKEN_PATH) < 0) {
        saved_errno = errno;
        if (temp_exists)
            unlink(temporary_path);
        OPENSSL_cleanse(key, SESSION_KEY_LENGTH);
        free(key);
        errno = saved_errno;
        return -1;
    }

    *session_key_out = key;
    *management_endpoint_out = session_management_endpoint;
    return 0;
}