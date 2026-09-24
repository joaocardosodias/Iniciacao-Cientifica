#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <syslog.h>
#include <wchar.h>
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#include <openssl/evp.h>
#include <openssl/rand.h>

static int write_all(int fd, const unsigned char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;

        buf += (size_t)n;
        len -= (size_t)n;
    }

    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    enum { NONCE_LEN = 12, TAG_LEN = 16, CHUNK_LEN = 16384 };
    unsigned char nonce[NONCE_LEN];
    unsigned char input[CHUNK_LEN];
    unsigned char output[CHUNK_LEN + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[TAG_LEN];
    EVP_CIPHER_CTX *ctx = NULL;
    char *output_path = NULL;
    size_t path_len;
    size_t suffix_len;
    int input_fd = -1;
    int output_fd = -1;
    int created = 0;
    int result = -1;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    path_len = strlen(path);
    suffix_len = strlen(ENCRYPTED_SUFFIX);
    if (path_len > SIZE_MAX - suffix_len - 1)
        return -1;

    output_path = malloc(path_len + suffix_len + 1);
    if (output_path == NULL)
        goto done;

    memcpy(output_path, path, path_len);
    memcpy(output_path + path_len, ENCRYPTED_SUFFIX, suffix_len + 1);

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto done;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto done;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LEN, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto done;

    output_fd = open(output_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (output_fd < 0)
        goto done;
    created = 1;

    if (write_all(output_fd, nonce, sizeof(nonce)) != 0)
        goto done;

    for (;;) {
        ssize_t n = read(input_fd, input, sizeof(input));
        int output_len;

        if (n < 0) {
            if (errno == EINTR)
                continue;
            goto done;
        }
        if (n == 0)
            break;

        if (EVP_EncryptUpdate(ctx, output, &output_len, input, (int)n) != 1 ||
            write_all(output_fd, output, (size_t)output_len) != 0)
            goto done;
    }

    {
        int output_len;

        if (EVP_EncryptFinal_ex(ctx, output, &output_len) != 1 ||
            write_all(output_fd, output, (size_t)output_len) != 0 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LEN, tag) != 1 ||
            write_all(output_fd, tag, sizeof(tag)) != 0)
            goto done;
    }

    if (close(input_fd) != 0) {
        input_fd = -1;
        goto done;
    }
    input_fd = -1;

    if (close(output_fd) != 0) {
        output_fd = -1;
        goto done;
    }
    output_fd = -1;
    result = 0;

done:
    if (input_fd >= 0)
        close(input_fd);
    if (output_fd >= 0)
        close(output_fd);
    if (result != 0 && created)
        unlink(output_path);
    EVP_CIPHER_CTX_free(ctx);
    free(output_path);
    return result;
}