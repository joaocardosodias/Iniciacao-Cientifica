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
#include <unistd.h>

static int
write_all(int fd, const unsigned char *buf, size_t len)
{
    size_t offset = 0;

    while (offset < len) {
        ssize_t n = write(fd, buf + offset, len - offset);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        offset += (size_t)n;
    }

    return 0;
}

int
write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    unsigned char nonce[12];
    unsigned char tag[16];
    unsigned char input[65536];
    unsigned char output[65552];
    unsigned char version = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    const char *suffix = ENCRYPTED_SUFFIX;
    char *final_path = NULL;
    char *temp_path = NULL;
    EVP_CIPHER_CTX *ctx = NULL;
    int input_fd = -1;
    int output_fd = -1;
    int temp_created = 0;
    int result = -1;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    if (asprintf(&final_path, "%s%s", path, suffix) < 0)
        goto done;
    if (asprintf(&temp_path, "%s.tmp", final_path) < 0)
        goto done;

    input_fd = open(path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto done;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1)
        goto done;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL ||
        EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1)
        goto done;

    output_fd = open(temp_path,
                     O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                     0600);
    if (output_fd < 0)
        goto done;
    temp_created = 1;

    if (write_all(output_fd, &version, sizeof(version)) != 0 ||
        write_all(output_fd, nonce, sizeof(nonce)) != 0)
        goto done;

    for (;;) {
        ssize_t n;
        int produced = 0;

        do {
            n = read(input_fd, input, sizeof(input));
        } while (n < 0 && errno == EINTR);

        if (n < 0)
            goto done;
        if (n == 0)
            break;

        if (EVP_EncryptUpdate(ctx, output, &produced, input, (int)n) != 1)
            goto done;
        if (write_all(output_fd, output, (size_t)produced) != 0)
            goto done;
    }

    if (close(input_fd) != 0) {
        input_fd = -1;
        goto done;
    }
    input_fd = -1;

    {
        int produced = 0;

        if (EVP_EncryptFinal_ex(ctx, output, &produced) != 1 ||
            write_all(output_fd, output, (size_t)produced) != 0 ||
            EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, sizeof(tag), tag) != 1 ||
            write_all(output_fd, tag, sizeof(tag)) != 0)
            goto done;
    }

    if (fsync(output_fd) != 0)
        goto done;
    if (close(output_fd) != 0) {
        output_fd = -1;
        goto done;
    }
    output_fd = -1;

    if (rename(temp_path, final_path) != 0)
        goto done;
    temp_created = 0;
    result = 0;

done:
    if (input_fd >= 0)
        close(input_fd);
    if (output_fd >= 0)
        close(output_fd);
    if (temp_created)
        unlink(temp_path);
    EVP_CIPHER_CTX_free(ctx);
    free(temp_path);
    free(final_path);
    return result;
}