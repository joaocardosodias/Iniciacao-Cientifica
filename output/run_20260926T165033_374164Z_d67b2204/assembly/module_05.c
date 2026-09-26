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
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

static int write_all(int fd, const unsigned char *buffer, size_t length)
{
    while (length > 0) {
        ssize_t written = write(fd, buffer, length);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        buffer += (size_t)written;
        length -= (size_t)written;
    }
    return 0;
}

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char input[16384];
    unsigned char output[16384 + EVP_MAX_BLOCK_LENGTH];
    unsigned char version = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    EVP_CIPHER_CTX *ctx = NULL;
    char *names = NULL;
    const char *final_path;
    char *temporary_path;
    size_t path_len;
    size_t suffix_len;
    size_t final_len;
    int input_fd = -1;
    int output_fd = -1;
    int temporary_created = 0;
    int result = -1;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    path_len = strlen(path);
    suffix_len = strlen(ENCRYPTED_SUFFIX);
    final_len = path_len + suffix_len;
    names = malloc(final_len + sizeof(".tmp"));
    if (names == NULL)
        return -1;

    memcpy(names, path, path_len);
    memcpy(names + path_len, ENCRYPTED_SUFFIX, suffix_len);
    names[final_len] = '\0';
    memcpy(names + final_len, ".tmp", sizeof(".tmp"));
    final_path = names;
    temporary_path = names + final_len;

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto done;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto done;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto done;
    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto done;

    output_fd = open(temporary_path,
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                     0600);
    if (output_fd < 0)
        goto done;
    temporary_created = 1;

    if (write_all(output_fd, &version, sizeof(version)) < 0 ||
        write_all(output_fd, nonce, sizeof(nonce)) < 0)
        goto done;

    for (;;) {
        ssize_t bytes_read = read(input_fd, input, sizeof(input));
        int output_len = 0;

        if (bytes_read < 0) {
            if (errno == EINTR)
                continue;
            goto done;
        }
        if (bytes_read == 0)
            break;

        if (EVP_EncryptUpdate(ctx, output, &output_len, input,
                              (int)bytes_read) != 1 ||
            output_len < 0 ||
            write_all(output_fd, output, (size_t)output_len) < 0)
            goto done;
    }

    {
        int output_len = 0;
        if (EVP_EncryptFinal_ex(ctx, output, &output_len) != 1 ||
            output_len < 0 ||
            write_all(output_fd, output, (size_t)output_len) < 0)
            goto done;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1 ||
        write_all(output_fd, tag, sizeof(tag)) < 0)
        goto done;

    if (close(input_fd) < 0) {
        input_fd = -1;
        goto done;
    }
    input_fd = -1;

    if (fsync(output_fd) < 0)
        goto done;
    if (close(output_fd) < 0) {
        output_fd = -1;
        goto done;
    }
    output_fd = -1;

    if (rename(temporary_path, final_path) < 0)
        goto done;

    temporary_created = 0;
    result = 0;

done:
    if (input_fd >= 0)
        close(input_fd);
    if (output_fd >= 0)
        close(output_fd);
    if (temporary_created)
        unlink(temporary_path);
    EVP_CIPHER_CTX_free(ctx);
    free(names);
    return result;
}