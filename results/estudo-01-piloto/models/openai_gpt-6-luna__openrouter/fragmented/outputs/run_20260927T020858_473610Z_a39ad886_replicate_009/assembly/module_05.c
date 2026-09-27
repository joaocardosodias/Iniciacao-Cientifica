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
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int
write_all(int fd, const unsigned char *buf, size_t len)
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

int
write_encrypted_sibling(const char *path, const unsigned char *key,
                        size_t key_len)
{
    int input_fd = -1;
    int temp_fd = -1;
    int temp_created = 0;
    int result = -1;
    EVP_CIPHER_CTX *ctx = NULL;
    char *final_path = NULL;
    char *temp_path = NULL;
    unsigned char nonce[12];
    unsigned char input_buf[65536];
    unsigned char output_buf[65536 + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[16];
    unsigned char version;
    size_t path_len;
    size_t suffix_len;
    size_t final_len;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    path_len = strlen(path);
    suffix_len = strlen(ENCRYPTED_SUFFIX);
    if (path_len > SIZE_MAX - suffix_len ||
        path_len + suffix_len > SIZE_MAX - sizeof(".tmp"))
        return -1;

    final_len = path_len + suffix_len;
    final_path = malloc(final_len + 1);
    temp_path = malloc(final_len + sizeof(".tmp"));
    if (final_path == NULL || temp_path == NULL)
        goto cleanup;

    memcpy(final_path, path, path_len);
    memcpy(final_path + path_len, ENCRYPTED_SUFFIX, suffix_len);
    final_path[final_len] = '\0';
    memcpy(temp_path, final_path, final_len);
    memcpy(temp_path + final_len, ".tmp", sizeof(".tmp"));

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto cleanup;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    temp_fd = open(temp_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                   0600);
    if (temp_fd < 0)
        goto cleanup;
    temp_created = 1;

    version = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    if (write_all(temp_fd, &version, sizeof(version)) < 0 ||
        write_all(temp_fd, nonce, sizeof(nonce)) < 0)
        goto cleanup;

    for (;;) {
        ssize_t n = read(input_fd, input_buf, sizeof(input_buf));
        int out_len = 0;

        if (n < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        if (n == 0)
            break;
        if (EVP_EncryptUpdate(ctx, output_buf, &out_len, input_buf, (int)n) != 1)
            goto cleanup;
        if (out_len > 0 && write_all(temp_fd, output_buf, (size_t)out_len) < 0)
            goto cleanup;
    }

    {
        int out_len = 0;
        if (EVP_EncryptFinal_ex(ctx, output_buf, &out_len) != 1)
            goto cleanup;
        if (out_len > 0 && write_all(temp_fd, output_buf, (size_t)out_len) < 0)
            goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1 ||
        write_all(temp_fd, tag, sizeof(tag)) < 0)
        goto cleanup;

    if (close(input_fd) < 0) {
        input_fd = -1;
        goto cleanup;
    }
    input_fd = -1;

    if (fsync(temp_fd) < 0)
        goto cleanup;
    if (close(temp_fd) < 0) {
        temp_fd = -1;
        goto cleanup;
    }
    temp_fd = -1;

    if (rename(temp_path, final_path) < 0)
        goto cleanup;
    temp_created = 0;
    result = 0;

cleanup:
    if (input_fd >= 0)
        close(input_fd);
    if (temp_fd >= 0)
        close(temp_fd);
    if (temp_created)
        unlink(temp_path);
    EVP_CIPHER_CTX_free(ctx);
    free(temp_path);
    free(final_path);
    return result;
}