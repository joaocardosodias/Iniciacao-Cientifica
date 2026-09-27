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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int write_all(int fd, const unsigned char *buf, size_t len)
{
    while (len > 0) {
        ssize_t n = write(fd, buf, len);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        buf += (size_t)n;
        len -= (size_t)n;
    }
    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    char *final_path = NULL;
    char *tmp_path = NULL;
    int input_fd = -1;
    int output_fd = -1;
    int tmp_created = 0;
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char input[65536];
    unsigned char output[65536 + EVP_MAX_BLOCK_LENGTH];
    int result = -1;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    if (asprintf(&final_path, "%s%s", path, ENCRYPTED_SUFFIX) < 0)
        goto cleanup;
    if (asprintf(&tmp_path, "%s.tmp", final_path) < 0)
        goto cleanup;

    output_fd = open(tmp_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (output_fd < 0)
        goto cleanup;
    tmp_created = 1;

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto cleanup;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto cleanup;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1)
        goto cleanup;
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1)
        goto cleanup;
    if (EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    {
        unsigned char header[13];
        int out_len;

        header[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;
        memcpy(header + 1, nonce, sizeof(nonce));
        if (write_all(output_fd, header, sizeof(header)) < 0)
            goto cleanup;

        for (;;) {
            ssize_t n = read(input_fd, input, sizeof(input));
            if (n < 0) {
                if (errno == EINTR)
                    continue;
                goto cleanup;
            }
            if (n == 0)
                break;
            if (EVP_EncryptUpdate(ctx, output, &out_len, input, (int)n) != 1)
                goto cleanup;
            if (out_len > 0 &&
                write_all(output_fd, output, (size_t)out_len) < 0)
                goto cleanup;
        }

        if (close(input_fd) < 0) {
            input_fd = -1;
            goto cleanup;
        }
        input_fd = -1;

        if (EVP_EncryptFinal_ex(ctx, output, &out_len) != 1)
            goto cleanup;
        if (out_len > 0 &&
            write_all(output_fd, output, (size_t)out_len) < 0)
            goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
        goto cleanup;
    if (write_all(output_fd, tag, sizeof(tag)) < 0)
        goto cleanup;
    if (fsync(output_fd) < 0)
        goto cleanup;
    if (close(output_fd) < 0) {
        output_fd = -1;
        goto cleanup;
    }
    output_fd = -1;

    if (rename(tmp_path, final_path) < 0)
        goto cleanup;
    tmp_created = 0;
    result = 0;

cleanup:
    {
        int saved_errno = errno;

        if (input_fd >= 0)
            close(input_fd);
        if (output_fd >= 0)
            close(output_fd);
        if (tmp_created)
            unlink(tmp_path);
        EVP_CIPHER_CTX_free(ctx);
        free(tmp_path);
        free(final_path);
        errno = saved_errno;
    }
    return result;
}