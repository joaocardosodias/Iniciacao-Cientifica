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

#define TRANSFORM_NONCE_SIZE 12
#define TRANSFORM_TAG_SIZE 16
#define TRANSFORM_BUFFER_SIZE 65536

static int write_all(int fd, const unsigned char *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t written = write(fd, buffer + offset, length - offset);

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
 * Encrypt one eligible regular file into a new destination file.
 *
 * The destination is published only after encryption has completed and the
 * temporary file has been flushed and closed. Existing destinations are never
 * overwritten. Returns 0 on success and -1 on failure, with errno set.
 */
int apply_transform(const char *source_path,
                    const char *destination_path,
                    const uint8_t *key)
{
    int source_fd = -1;
    int temporary_fd = -1;
    int result = -1;
    int saved_errno = 0;
    int published = 0;
    char *temporary_path = NULL;
    EVP_CIPHER_CTX *context = NULL;
    struct stat source_stat;
    unsigned char nonce[TRANSFORM_NONCE_SIZE];
    unsigned char tag[TRANSFORM_TAG_SIZE];
    unsigned char input_buffer[TRANSFORM_BUFFER_SIZE];
    unsigned char output_buffer[TRANSFORM_BUFFER_SIZE + EVP_MAX_BLOCK_LENGTH];

    if (source_path == NULL || destination_path == NULL || key == NULL ||
        source_path[0] == '\0' || destination_path[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    source_fd = open(source_path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (source_fd < 0)
        goto cleanup;

    if (fstat(source_fd, &source_stat) < 0)
        goto cleanup;
    if (!S_ISREG(source_stat.st_mode)) {
        errno = EINVAL;
        goto cleanup;
    }

    if (RAND_bytes(nonce, sizeof(nonce)) != 1) {
        errno = EIO;
        goto cleanup;
    }

    context = EVP_CIPHER_CTX_new();
    if (context == NULL) {
        errno = ENOMEM;
        goto cleanup;
    }

    if (EVP_EncryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                            (int)sizeof(nonce), NULL) != 1 ||
        EVP_EncryptInit_ex(context, NULL, NULL, key, nonce) != 1) {
        errno = EIO;
        goto cleanup;
    }

    {
        size_t destination_length = strlen(destination_path);
        static const char suffix[] = ".tmp.XXXXXX";

        if (destination_length > SIZE_MAX - sizeof(suffix)) {
            errno = ENAMETOOLONG;
            goto cleanup;
        }

        temporary_path = malloc(destination_length + sizeof(suffix));
        if (temporary_path == NULL) {
            errno = ENOMEM;
            goto cleanup;
        }

        memcpy(temporary_path, destination_path, destination_length);
        memcpy(temporary_path + destination_length, suffix, sizeof(suffix));
    }

    temporary_fd = mkostemp(temporary_path, O_CLOEXEC);
    if (temporary_fd < 0)
        goto cleanup;

    if (write_all(temporary_fd, nonce, sizeof(nonce)) < 0)
        goto cleanup;

    for (;;) {
        ssize_t bytes_read = read(source_fd, input_buffer, sizeof(input_buffer));

        if (bytes_read < 0) {
            if (errno == EINTR)
                continue;
            goto cleanup;
        }
        if (bytes_read == 0)
            break;

        {
            int bytes_out = 0;

            if (EVP_EncryptUpdate(context, output_buffer, &bytes_out,
                                  input_buffer, (int)bytes_read) != 1) {
                errno = EIO;
                goto cleanup;
            }
            if (bytes_out < 0 ||
                write_all(temporary_fd, output_buffer, (size_t)bytes_out) < 0)
                goto cleanup;
        }
    }

    {
        int bytes_out = 0;

        if (EVP_EncryptFinal_ex(context, output_buffer, &bytes_out) != 1) {
            errno = EIO;
            goto cleanup;
        }
        if (bytes_out < 0 ||
            write_all(temporary_fd, output_buffer, (size_t)bytes_out) < 0)
            goto cleanup;
    }

    if (EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_GET_TAG,
                            (int)sizeof(tag), tag) != 1) {
        errno = EIO;
        goto cleanup;
    }

    if (write_all(temporary_fd, tag, sizeof(tag)) < 0)
        goto cleanup;

    if (fsync(temporary_fd) < 0)
        goto cleanup;

    if (close(temporary_fd) < 0) {
        temporary_fd = -1;
        goto cleanup;
    }
    temporary_fd = -1;

    if (close(source_fd) < 0) {
        source_fd = -1;
        goto cleanup;
    }
    source_fd = -1;

    /*
     * link() publishes the completed file without replacing an existing
     * destination. The temporary file is created beside the destination, so
     * both names are on the same filesystem.
     */
    if (link(temporary_path, destination_path) < 0)
        goto cleanup;
    published = 1;
    result = 0;

cleanup:
    saved_errno = errno;

    if (temporary_fd >= 0)
        (void)close(temporary_fd);
    if (source_fd >= 0)
        (void)close(source_fd);
    if (context != NULL)
        EVP_CIPHER_CTX_free(context);

    if (temporary_path != NULL) {
        if (unlink(temporary_path) < 0 && errno != ENOENT && result == 0) {
            /*
             * The destination already names the complete file. Failure to
             * remove the extra temporary hard link does not invalidate it.
             */
        }
        free(temporary_path);
    }

    if (result < 0) {
        (void)published;
        errno = saved_errno;
    }

    return result;
}

#ifdef APPLY_TRANSFORM_TEST

#include <dirent.h>

static int test_write_all(int fd, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    size_t offset = 0;

    while (offset < length) {
        ssize_t count = write(fd, bytes + offset, length - offset);

        if (count < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (count == 0) {
            errno = EIO;
            return -1;
        }
        offset += (size_t)count;
    }

    return 0;
}

static int read_entire_file(const char *path, unsigned char **data,
                            size_t *length)
{
    int fd = -1;
    struct stat st;
    unsigned char *buffer = NULL;
    size_t offset = 0;

    *data = NULL;
    *length = 0;

    fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0 ||
        (uintmax_t)st.st_size > SIZE_MAX) {
        int saved = errno ? errno : EINVAL;
        close(fd);
        errno = saved;
        return -1;
    }

    buffer = malloc(st.st_size == 0 ? 1 : (size_t)st.st_size);
    if (buffer == NULL) {
        close(fd);
        errno = ENOMEM;
        return -1;
    }

    while (offset < (size_t)st.st_size) {
        ssize_t count = read(fd, buffer + offset, (size_t)st.st_size - offset);

        if (count < 0) {
            if (errno == EINTR)
                continue;
            free(buffer);
            close(fd);
            return -1;
        }
        if (count == 0) {
            free(buffer);
            close(fd);
            errno = EIO;
            return -1;
        }
        offset += (size_t)count;
    }

    if (close(fd) < 0) {
        free(buffer);
        return -1;
    }

    *data = buffer;
    *length = offset;
    return 0;
}

static int decrypt_and_compare(const unsigned char *encoded,
                               size_t encoded_length,
                               const unsigned char *key,
                               const unsigned char *expected,
                               size_t expected_length)
{
    EVP_CIPHER_CTX *context = NULL;
    unsigned char *plaintext = NULL;
    size_t ciphertext_length;
    int output_length = 0;
    int final_length = 0;
    int ok = 0;

    if (encoded_length < TRANSFORM_NONCE_SIZE + TRANSFORM_TAG_SIZE)
        return 0;

    ciphertext_length =
        encoded_length - TRANSFORM_NONCE_SIZE - TRANSFORM_TAG_SIZE;
    plaintext = malloc(ciphertext_length == 0 ? 1 : ciphertext_length);
    if (plaintext == NULL)
        return 0;

    context = EVP_CIPHER_CTX_new();
    if (context == NULL)
        goto done;

    if (EVP_DecryptInit_ex(context, EVP_aes_256_gcm(), NULL, NULL, NULL) != 1 ||
        EVP_CIPHER_CTX_ctrl(context, EVP_CTRL_GCM_SET_IVLEN,
                            TRANSFORM_NONCE_SIZE, NULL) != 1 ||
        EVP_DecryptInit_ex(context, NULL, NULL, key, encoded) != 1)
        goto done;

    if (ciphertext_length > 0 &&
        EVP_DecryptUpdate(context, plaintext, &output_length,
                          encoded + TRANSFORM_NONCE_SIZE,
                          (int)ciphertext_length) != 1)
        goto done;

    if (EVP_CIPHER_CTX_ctrl(
            context, EVP_CTRL_GCM_SET_TAG, TRANSFORM_TAG_SIZE,
            (void *)(encoded + TRANSFORM_NONCE_SIZE + ciphertext_length)) != 1)
        goto done;

    if (EVP_DecryptFinal_ex(context, plaintext + output_length,
                            &final_length) != 1)
        goto done;

    if ((size_t)(output_length + final_length) != expected_length)
        goto done;
    if (expected_length != 0 &&
        memcmp(plaintext, expected, expected_length) != 0)
        goto done;

    ok = 1;

done:
    EVP_CIPHER_CTX_free(context);
    free(plaintext);
    return ok;
}

static int files_equal(const char *first, const char *second)
{
    unsigned char *a = NULL;
    unsigned char *b = NULL;
    size_t a_length = 0;
    size_t b_length = 0;
    int equal = 0;

    if (read_entire_file(first, &a, &a_length) < 0)
        goto done;
    if (read_entire_file(second, &b, &b_length) < 0)
        goto done;

    equal = a_length == b_length &&
            (a_length == 0 || memcmp(a, b, a_length) == 0);

done:
    free(a);
    free(b);
    return equal;
}

int main(void)
{
    char directory_template[] = "/tmp/apply-transform-test.XXXXXX";
    char *directory = mkdtemp(directory_template);
    char source_path[PATH_MAX];
    char destination_path[PATH_MAX];
    char second_destination_path[PATH_MAX];
    char missing_destination_path[PATH_MAX];
    char directory_source_path[PATH_MAX];
    static const unsigned char original[] =
        "archival test data\0with binary bytes\xff\x10";
    uint8_t key[32];
    unsigned char *encoded = NULL;
    unsigned char *second_encoded = NULL;
    size_t encoded_length = 0;
    size_t second_encoded_length = 0;
    int source_fd = -1;
    int directory_fd = -1;
    int exit_status = 1;
    size_t i;

    if (directory == NULL)
        goto done;

    if (snprintf(source_path, sizeof(source_path), "%s/source.bin",
                 directory) >= (int)sizeof(source_path) ||
        snprintf(destination_path, sizeof(destination_path), "%s/copy.enc",
                 directory) >= (int)sizeof(destination_path) ||
        snprintf(second_destination_path, sizeof(second_destination_path),
                 "%s/copy-second.enc", directory) >=
            (int)sizeof(second_destination_path) ||
        snprintf(missing_destination_path, sizeof(missing_destination_path),
                 "%s/no-such-directory/copy.enc", directory) >=
            (int)sizeof(missing_destination_path) ||
        snprintf(directory_source_path, sizeof(directory_source_path),
                 "%s", directory) >= (int)sizeof(directory_source_path))
        goto done;

    for (i = 0; i < sizeof(key); ++i)
        key[i] = (uint8_t)(i * 7U + 3U);

    source_fd = open(source_path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC,
                     0600);
    if (source_fd < 0)
        goto done;
    if (test_write_all(source_fd, original, sizeof(original)) < 0)
        goto done;
    if (close(source_fd) < 0) {
        source_fd = -1;
        goto done;
    }
    source_fd = -1;

    if (!files_equal(source_path, source_path))
        goto done;
    if (apply_transform(source_path, destination_path, key) != 0)
        goto done;
    if (read_entire_file(destination_path, &encoded, &encoded_length) < 0)
        goto done;

    if (encoded_length < TRANSFORM_NONCE_SIZE + TRANSFORM_TAG_SIZE)
        goto done;
    if (!decrypt_and_compare(encoded, encoded_length, key, original,
                             sizeof(original)))
        goto done;
    if (!files_equal(source_path, source_path))
        goto done;

    if (apply_transform(source_path, second_destination_path, key) != 0)
        goto done;
    if (read_entire_file(second_destination_path, &second_encoded,
                         &second_encoded_length) < 0)
        goto done;
    if (second_encoded_length < TRANSFORM_NONCE_SIZE + TRANSFORM_TAG_SIZE)
        goto done;
    if (memcmp(encoded, second_encoded, TRANSFORM_NONCE_SIZE) == 0)
        goto done;
    if (!decrypt_and_compare(second_encoded, second_encoded_length, key,
                             original, sizeof(original)))
        goto done;

    if (apply_transform(directory_source_path, destination_path, key) == 0)
        goto done;
    if (apply_transform(source_path, missing_destination_path, key) == 0)
        goto done;
    if (apply_transform(source_path, second_destination_path, key) == 0)
        goto done;
    if (apply_transform(source_path, destination_path, NULL) == 0)
        goto done;
    if (!files_equal(source_path, source_path))
        goto done;

    directory_fd = open(directory_source_path, O_RDONLY | O_DIRECTORY |
                                                   O_CLOEXEC);
    if (directory_fd < 0)
        goto done;
    if (close(directory_fd) < 0) {
        directory_fd = -1;
        goto done;
    }
    directory_fd = -1;

    exit_status = 0;

done:
    if (source_fd >= 0)
        close(source_fd);
    if (directory_fd >= 0)
        close(directory_fd);
    free(encoded);
    free(second_encoded);

    if (directory != NULL) {
        if (source_path[0] != '\0')
            unlink(source_path);
        if (destination_path[0] != '\0')
            unlink(destination_path);
        if (second_destination_path[0] != '\0')
            unlink(second_destination_path);
        rmdir(directory);
    }

    return exit_status;
}