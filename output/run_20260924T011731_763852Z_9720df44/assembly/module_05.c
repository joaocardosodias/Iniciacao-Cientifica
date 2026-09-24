#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int write_all(int fd, const unsigned char *buf, size_t len)
{
    size_t offset = 0;

    while (offset < len) {
        ssize_t written = write(fd, buf + offset, len - offset);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        offset += (size_t)written;
    }

    return 0;
}

/*
 * Encrypts source_path using AES-256-GCM and writes a copy to
 * source_path + ".enc". The output consists of a 12-byte nonce, the
 * ciphertext, and a 16-byte authentication tag. The source is never
 * modified. Returns 0 on success and -1 on failure, setting errno.
 */
int transform_file(const char *source_path, const uint8_t *key)
{
    enum {
        NONCE_LENGTH = 12,
        TAG_LENGTH = 16,
        IO_BLOCK_SIZE = 65536
    };

    int input_fd = -1;
    int output_fd = -1;
    int result = -1;
    int temp_exists = 0;
    int published = 0;
    int saved_errno = 0;
    size_t source_len;
    size_t destination_len;
    size_t temp_suffix_len;
    char *destination_path = NULL;
    char *temp_path = NULL;
    unsigned char nonce[NONCE_LENGTH];
    unsigned char input_buffer[IO_BLOCK_SIZE];
    unsigned char output_buffer[IO_BLOCK_SIZE + EVP_MAX_BLOCK_LENGTH];
    unsigned char tag[TAG_LENGTH];
    EVP_CIPHER_CTX *ctx = NULL;

    if (source_path == NULL || key == NULL) {
        errno = EINVAL;
        return -1;
    }

    source_len = strlen(source_path);
    if (source_len > SIZE_MAX - sizeof(".enc")) {
        errno = ENAMETOOLONG;
        return -1;
    }
    destination_len = source_len + sizeof(".enc") - 1;
    temp_suffix_len = sizeof(".tmp.XXXXXX") - 1;
    if (destination_len > SIZE_MAX - temp_suffix_len - 1) {
        errno = ENAMETOOLONG;
        return -1;
    }

    destination_path = malloc(destination_len + 1);
    temp_path = malloc(destination_len + temp_suffix_len + 1);
    if (destination_path == NULL || temp_path == NULL) {
        errno = ENOMEM;
        goto cleanup;
    }

    memcpy(destination_path, source_path, source_len);
    memcpy(destination_path + source_len, ".enc", sizeof(".enc"));
    memcpy(temp_path, destination_path, destination_len);
    memcpy(temp_path + destination_len, ".tmp.XXXXXX",
           sizeof(".tmp.XXXXXX"));

    input_fd = open(source_path, O_RDONLY | O_CLOEXEC);
    if (input_fd < 0)
        goto cleanup;

    output_fd = mkstemp(temp_path);
    if (output_fd < 0)
        goto cleanup;
    temp_exists = 1;

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        errno = EIO;
        goto cleanup;
    }

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) {
        errno = ENOMEM;
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LENGTH, NULL) != 1 ||
        EVP_EncryptInit_ex(ctx, NULL, NULL, key, nonce) != 1) {
        errno = EIO;
        goto cleanup;
    }

    if (write_all(output_fd, nonce, sizeof(nonce)) != 0)
        goto cleanup;

    for (;;) {
        ssize_t bytes_read = read(input_fd, input_buffer, sizeof(input_buffer));
        int output_length = 0;

        if (bytes_read < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        if (bytes_read == 0)
            break;

        if (EVP_EncryptUpdate(ctx, output_buffer, &output_length,
                              input_buffer, (int)bytes_read) != 1) {
            errno = EIO;
            goto cleanup;
        }
        if (output_length < 0 ||
            write_all(output_fd, output_buffer, (size_t)output_length) != 0)
            goto cleanup;
    }

    {
        int final_length = 0;

        if (EVP_EncryptFinal_ex(ctx, output_buffer, &final_length) != 1) {
            errno = EIO;
            goto cleanup;
        }
        if (final_length < 0 ||
            write_all(output_fd, output_buffer, (size_t)final_length) != 0)
            goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, TAG_LENGTH, tag) != 1) {
        errno = EIO;
        goto cleanup;
    }
    if (write_all(output_fd, tag, sizeof(tag)) != 0)
        goto cleanup;

    if (fsync(output_fd) != 0)
        goto cleanup;

    EVP_CIPHER_CTX_free(ctx);
    ctx = NULL;

    if (close(output_fd) != 0) {
        output_fd = -1;
        goto cleanup;
    }
    output_fd = -1;

    if (close(input_fd) != 0) {
        input_fd = -1;
        goto cleanup;
    }
    input_fd = -1;

    /*
     * link() publishes atomically and fails if destination_path already
     * exists, unlike rename(), which could replace an existing file.
     */
    if (link(temp_path, destination_path) != 0)
        goto cleanup;
    published = 1;

    if (unlink(temp_path) != 0)
        goto cleanup;
    temp_exists = 0;

    result = 0;

cleanup:
    if (result != 0)
        saved_errno = errno != 0 ? errno : EIO;

    if (ctx != NULL)
        EVP_CIPHER_CTX_free(ctx);
    if (output_fd >= 0)
        (void)close(output_fd);
    if (input_fd >= 0)
        (void)close(input_fd);

    if (result != 0) {
        if (published)
            (void)unlink(destination_path);
        if (temp_exists)
            (void)unlink(temp_path);
    }

    free(temp_path);
    free(destination_path);

    if (result != 0)
        errno = saved_errno;

    return result;
}

#ifdef TRANSFORM_FILE_TEST

#include <dirent.h>
#include <inttypes.h>

static int test_write_file(const char *path, const unsigned char *data, size_t len)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    int saved_errno;

    if (fd < 0)
        return -1;
    if (write_all(fd, data, len) != 0) {
        saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    if (close(fd) != 0)
        return -1;
    return 0;
}

static int test_read_file(const char *path, unsigned char **data, size_t *len)
{
    struct stat st;
    unsigned char *buffer;
    size_t offset = 0;
    int fd;

    *data = NULL;
    *len = 0;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) != 0 || st.st_size < 0 ||
        (uintmax_t)st.st_size > SIZE_MAX) {
        int saved_errno = errno != 0 ? errno : EOVERFLOW;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }

    buffer = malloc(st.st_size == 0 ? 1 : (size_t)st.st_size);
    if (buffer == NULL) {
        (void)close(fd);
        errno = ENOMEM;
        return -1;
    }

    while (offset < (size_t)st.st_size) {
        ssize_t n = read(fd, buffer + offset, (size_t)st.st_size - offset);

        if (n < 0) {
            if (errno == EINTR)
                continue;
            {
                int saved_errno = errno;
                free(buffer);
                (void)close(fd);
                errno = saved_errno;
            }
            return -1;
        }
        if (n == 0) {
            free(buffer);
            (void)close(fd);
            errno = EIO;
            return -1;
        }
        offset += (size_t)n;
    }

    if (close(fd) != 0) {
        int saved_errno = errno;
        free(buffer);
        errno = saved_errno;
        return -1;
    }

    *data = buffer;
    *len = offset;
    return 0;
}

static int test_decrypt_and_compare(const unsigned char *encrypted,
                                   size_t encrypted_len,
                                   const unsigned char *expected,
                                   size_t expected_len,
                                   const uint8_t *key)
{
    enum { NONCE_LENGTH = 12, TAG_LENGTH = 16 };
    EVP_CIPHER_CTX *ctx = NULL;
    unsigned char *plain = NULL;
    size_t ciphertext_len;
    size_t plain_capacity;
    int update_len = 0;
    int final_len = 0;
    int ok = 0;

    if (encrypted_len < NONCE_LENGTH + TAG_LENGTH)
        return -1;

    ciphertext_len = encrypted_len - NONCE_LENGTH - TAG_LENGTH;
    if (ciphertext_len != expected_len ||
        ciphertext_len > SIZE_MAX - EVP_MAX_BLOCK_LENGTH)
        return -1;

    plain_capacity = ciphertext_len + EVP_MAX_BLOCK_LENGTH;
    plain = malloc(plain_capacity == 0 ? 1 : plain_capacity);
    if (plain == NULL)
        return -1;

    ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL)
        goto done;

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, NONCE_LENGTH, NULL) != 1 ||
        EVP_DecryptInit_ex(ctx, NULL, NULL, key, encrypted) != 1)
        goto done;

    if (ciphertext_len != 0 &&
        EVP_DecryptUpdate(ctx, plain, &update_len,
                          encrypted + NONCE_LENGTH, (int)ciphertext_len) != 1)
        goto done;

    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, TAG_LENGTH,
                            (void *)(encrypted + NONCE_LENGTH + ciphertext_len)) != 1)
        goto done;

    if (EVP_DecryptFinal_ex(ctx, plain + update_len, &final_len) != 1)
        goto done;

    if ((size_t)(update_len + final_len) != expected_len ||
        (expected_len != 0 && memcmp(plain, expected, expected_len) != 0))
        goto done;

    ok = 1;

done:
    EVP_CIPHER_CTX_free(ctx);
    free(plain);
    return ok ? 0 : -1;
}

static int test_run_case(const char *directory, const char *name,
                         const unsigned char *contents, size_t contents_len,
                         const uint8_t *key)
{
    char source[PATH_MAX];
    char destination[PATH_MAX];
    unsigned char *original = NULL;
    unsigned char *encrypted = NULL;
    size_t original_len = 0;
    size_t encrypted_len = 0;
    int ok = -1;

    if (snprintf(source, sizeof(source), "%s/%s", directory, name) >=
            (int)sizeof(source) ||
        snprintf(destination, sizeof(destination), "%s.enc", source) >=
            (int)sizeof(destination))
        return -1;

    if (test_write_file(source, contents, contents_len) != 0)
        goto done;
    if (transform_file(source, key) != 0)
        goto done;
    if (test_read_file(source, &original, &original_len) != 0 ||
        original_len != contents_len ||
        (contents_len != 0 && memcmp(original, contents, contents_len) != 0))
        goto done;
    if (test_read_file(destination, &encrypted, &encrypted_len) != 0 ||
        encrypted_len != contents_len + 12 + 16)
        goto done;
    if (test_decrypt_and_compare(encrypted, encrypted_len, contents,
                                 contents_len, key) != 0)
        goto done;

    ok = 0;

done:
    free(original);
    free(encrypted);
    (void)unlink(destination);
    (void)unlink(source);
    return ok;
}

static int test_existing_destination(const char *directory, const uint8_t *key)
{
    char source[PATH_MAX];
    char destination[PATH_MAX];
    static const unsigned char source_data[] = "source";
    static const unsigned char sentinel[] = "do not replace";
    unsigned char *readback = NULL;
    size_t readback_len = 0;
    int ok = -1;

    if (snprintf(source, sizeof(source), "%s/existing-source", directory) >=
            (int)sizeof(source) ||
        snprintf(destination, sizeof(destination), "%s.enc", source) >=
            (int)sizeof(destination))
        return -1;

    if (test_write_file(source, source_data, sizeof(source_data) - 1) != 0 ||
        test_write_file(destination, sentinel, sizeof(sentinel) - 1) != 0)
        goto done;

    if (transform_file(source, key) == 0)
        goto done;
    if (test_read_file(destination, &readback, &readback_len) != 0 ||
        readback_len != sizeof(sentinel) - 1 ||
        memcmp(readback, sentinel, sizeof(sentinel) - 1) != 0)
        goto done;

    ok = 0;

done:
    free(readback);
    (void)unlink(destination);
    (void)unlink(source);
    return ok;
}

static int test_read_failure_cleanup(const char *directory, const uint8_t *key)
{
    char source[PATH_MAX];
    char destination[PATH_MAX];
    DIR *dir = NULL;
    struct dirent *entry;
    int found_temp = 0;
    int ok = -1;

    if (snprintf(source, sizeof(source), "%s/read-failure-dir", directory) >=
            (int)sizeof(source) ||
        snprintf(destination, sizeof(destination), "%s.enc", source) >=
            (int)sizeof(destination))
        return -1;

    if (mkdir(source, 0700) != 0)
        return -1;
    if (transform_file(source, key) == 0)
        goto done;
    if (access(destination, F_OK) == 0 || errno != ENOENT)
        goto done;

    dir = opendir(directory);
    if (dir == NULL)
        goto done;

    while ((entry = readdir(dir)) != NULL) {
        if (strncmp(entry->d_name, "read-failure-dir.enc.tmp.", 25) == 0) {
            found_temp = 1;
            break;
        }
    }
    if (closedir(dir) != 0) {
        dir = NULL;
        goto done;
    }
    dir = NULL;

    if (found_temp)
        goto done;
    ok = 0;

done:
    if (dir != NULL)
        (void)closedir(dir);
    (void)unlink(destination);
    (void)rmdir(source);
    return ok;
}

int main(void)
{
    char directory_template[] = "/tmp/transform-file-test.XXXXXX";
    char *directory;
    uint8_t key[32];
    unsigned char *large_contents;
    size_t large_len = 300000;
    size_t i;
    int status = 1;

    for (i = 0; i < sizeof(key); ++i)
        key[i] = (uint8_t)(i * 7U + 3U);

    directory = mkdtemp(directory_template);
    if (directory == NULL) {
        perror("mkdtemp");
        return 1;
    }

    large_contents = malloc(large_len);
    if (large_contents == NULL) {
        perror("malloc");
        (void)rmdir(directory);
        return 1;
    }
    for (i = 0; i < large_len; ++i)
        large_contents[i] = (unsigned char)((i * 31U + i / 127U) & 0xffU);

    if (test_run_case(directory, "empty", NULL, 0, key) != 0) {
        fprintf(stderr, "empty-file test failed\n");
        goto done;
    }
    if (test_run_case(directory, "multi-block", large_contents, large_len, key) != 0) {
        fprintf(stderr, "multi-block, format, or source-preservation test failed\n");
        goto done;
    }
    if (test_existing_destination(directory, key) != 0) {
        fprintf(stderr, "existing-destination test failed\n");
        goto done;
    }
    if (test_read_failure_cleanup(directory, key) != 0) {
        fprintf(stderr, "read-failure cleanup test failed\n");
        goto done;
    }

    status = 0;

done:
    free(large_contents);
    (void)rmdir(directory);
    return status;
}

#endif