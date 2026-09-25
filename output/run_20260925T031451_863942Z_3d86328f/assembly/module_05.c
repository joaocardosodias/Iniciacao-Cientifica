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
write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    unsigned char nonce[12];
    unsigned char input_buf[65536];
    unsigned char output_buf[65536 + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[16];
    char *output_path = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int input_fd = -1;
    int output_fd = -1;
    int output_created = 0;
    int result = -1;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    if (asprintf(&output_path, "%s%s", path, ENCRYPTED_SUFFIX) < 0)
        return -1;

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto cleanup;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto cleanup;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto cleanup;

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto cleanup;

    output_fd = open(output_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (output_fd < 0)
        goto cleanup;
    output_created = 1;

    if (write_all(output_fd, nonce, sizeof(nonce)) < 0)
        goto cleanup;

    for (;;) {
        ssize_t bytes_read = read(input_fd, input_buf, sizeof(input_buf));
        int bytes_written = 0;

        if (bytes_read < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        if (bytes_read == 0)
            break;

        if (EVP_EncryptUpdate(ctx, output_buf, &bytes_written, input_buf,
                              (int)bytes_read) != 1)
            goto cleanup;
        if (bytes_written > 0 &&
            write_all(output_fd, output_buf, (size_t)bytes_written) < 0)
            goto cleanup;
    }

    {
        int bytes_written = 0;
        if (EVP_EncryptFinal_ex(ctx, output_buf, &bytes_written) != 1)
            goto cleanup;
        if (bytes_written > 0 &&
            write_all(output_fd, output_buf, (size_t)bytes_written) < 0)
            goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1)
        goto cleanup;
    if (write_all(output_fd, tag, sizeof(tag)) < 0)
        goto cleanup;

    if (close(input_fd) < 0) {
        input_fd = -1;
        goto cleanup;
    }
    input_fd = -1;

    if (close(output_fd) < 0) {
        output_fd = -1;
        goto cleanup;
    }
    output_fd = -1;

    result = 0;

cleanup:
    if (input_fd >= 0)
        close(input_fd);
    if (output_fd >= 0)
        close(output_fd);
    if (result != 0 && output_created)
        unlink(output_path);
    EVP_CIPHER_CTX_free(ctx);
    free(output_path);
    return result;
}