#define _GNU_SOURCE
#include <ctype.h>
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <openssl/evp.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Interface proposed for projects without an existing configuration API.
 *
 * Validation criteria:
 * - The target directory must be an existing absolute directory, contain no
 *   "." or ".." components, and contain no symbolic-link components.
 * - Its canonical path must be equal to or below one of the explicitly
 *   authorized directories. Authorized directories are subject to the same
 *   path checks.
 * - The extension and every allowlist entry must have the form ".suffix",
 *   where suffix is 1–16 ASCII letters or digits. Comparisons are
 *   case-insensitive.
 * - An optional Base64 field is for non-secret data only. It must be strict,
 *   canonical Base64, nonempty, and decode to at most 3072 bytes.
 * - Validation is read-only: it does not access the network or modify files.
 *
 * Errors are returned through the caller-provided buffer and deliberately
 * never include configuration values, which could contain secrets.
 */
#define CONFIG_MAX_PATHS 128U
#define CONFIG_MAX_EXTENSIONS 128U
#define CONFIG_MAX_EXTENSION_LENGTH 17U
#define CONFIG_MAX_BASE64_LENGTH 4096U
#define CONFIG_MAX_BASE64_DECODED 3072U

enum config_validation_result {
    CONFIG_VALID = 0,
    CONFIG_INVALID = 1
};

struct service_config {
    const char *target_directory;
    const char *extension;
    const char *base64_nonsecret;
};

struct validation_policy {
    const char *const *authorized_directories;
    size_t authorized_directory_count;
    const char *const *allowed_extensions;
    size_t allowed_extension_count;
};

static void
set_error(char *error, size_t error_size, const char *message)
{
    if (error != NULL && error_size > 0U) {
        (void)snprintf(error, error_size, "%s", message);
    }
}

static bool
has_valid_absolute_path_syntax(const char *path)
{
    size_t length;
    size_t i;

    if (path == NULL) {
        return false;
    }

    length = strnlen(path, PATH_MAX);
    if (length == 0U || length >= PATH_MAX || path[0] != '/') {
        return false;
    }

    i = 1U;
    while (i < length) {
        size_t start;
        size_t component_length;

        while (i < length && path[i] == '/') {
            ++i;
        }
        if (i >= length) {
            break;
        }

        start = i;
        while (i < length && path[i] != '/') {
            ++i;
        }
        component_length = i - start;

        if ((component_length == 1U && path[start] == '.') ||
            (component_length == 2U && path[start] == '.' &&
             path[start + 1U] == '.')) {
            return false;
        }
    }

    return true;
}

/*
 * Open an absolute directory one component at a time with O_NOFOLLOW. This
 * rejects symbolic links in every component, including components which
 * realpath() would otherwise silently resolve.
 */
static int
open_absolute_directory_without_symlinks(const char *path)
{
    int directory_fd;
    size_t length;
    size_t i;

    if (!has_valid_absolute_path_syntax(path)) {
        errno = EINVAL;
        return -1;
    }

    directory_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0) {
        return -1;
    }

    length = strlen(path);
    i = 1U;

    while (i < length) {
        size_t start;
        size_t component_length;
        char component[PATH_MAX];
        int next_fd;

        while (i < length && path[i] == '/') {
            ++i;
        }
        if (i >= length) {
            break;
        }

        start = i;
        while (i < length && path[i] != '/') {
            ++i;
        }
        component_length = i - start;

        if (component_length == 0U ||
            component_length >= sizeof(component)) {
            (void)close(directory_fd);
            errno = ENAMETOOLONG;
            return -1;
        }

        memcpy(component, path + start, component_length);
        component[component_length] = '\0';

        next_fd = openat(directory_fd, component,
                         O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        if (next_fd < 0) {
            int saved_errno = errno;
            (void)close(directory_fd);
            errno = saved_errno;
            return -1;
        }

        (void)close(directory_fd);
        directory_fd = next_fd;
    }

    return directory_fd;
}

/*
 * Return a canonical path only after safely opening the directory. The
 * device/inode comparison ensures that realpath() identified the same
 * directory that was opened without following symbolic links.
 */
static bool
canonicalize_directory(const char *path, char canonical[PATH_MAX])
{
    int fd;
    struct stat opened_stat;
    struct stat resolved_stat;

    fd = open_absolute_directory_without_symlinks(path);
    if (fd < 0) {
        return false;
    }

    if (fstat(fd, &opened_stat) != 0 || !S_ISDIR(opened_stat.st_mode)) {
        (void)close(fd);
        return false;
    }

    if (realpath(path, canonical) == NULL ||
        stat(canonical, &resolved_stat) != 0 ||
        !S_ISDIR(resolved_stat.st_mode) ||
        opened_stat.st_dev != resolved_stat.st_dev ||
        opened_stat.st_ino != resolved_stat.st_ino) {
        (void)close(fd);
        return false;
    }

    (void)close(fd);
    return true;
}

static bool
is_within_directory(const char *directory, const char *candidate)
{
    size_t directory_length;

    if (directory == NULL || candidate == NULL) {
        return false;
    }

    directory_length = strlen(directory);

    if (directory_length == 1U && directory[0] == '/') {
        return candidate[0] == '/';
    }

    if (strncmp(directory, candidate, directory_length) != 0) {
        return false;
    }

    return candidate[directory_length] == '\0' ||
           candidate[directory_length] == '/';
}

static bool
is_valid_extension(const char *extension)
{
    size_t length;
    size_t i;

    if (extension == NULL) {
        return false;
    }

    length = strnlen(extension, CONFIG_MAX_EXTENSION_LENGTH + 1U);
    if (length < 2U || length > CONFIG_MAX_EXTENSION_LENGTH ||
        extension[0] != '.') {
        return false;
    }

    for (i = 1U; i < length; ++i) {
        unsigned char ch = (unsigned char)extension[i];
        if (!((ch >= (unsigned char)'a' && ch <= (unsigned char)'z') ||
              (ch >= (unsigned char)'A' && ch <= (unsigned char)'Z') ||
              (ch >= (unsigned char)'0' && ch <= (unsigned char)'9'))) {
            return false;
        }
    }

    return true;
}

static bool
extensions_equal_case_insensitive(const char *left, const char *right)
{
    size_t i;
    size_t left_length;
    size_t right_length;

    left_length = strlen(left);
    right_length = strlen(right);
    if (left_length != right_length) {
        return false;
    }

    for (i = 0U; i < left_length; ++i) {
        unsigned char left_ch = (unsigned char)left[i];
        unsigned char right_ch = (unsigned char)right[i];

        if (left_ch >= (unsigned char)'A' &&
            left_ch <= (unsigned char)'Z') {
            left_ch = (unsigned char)(left_ch - (unsigned char)'A' +
                                      (unsigned char)'a');
        }
        if (right_ch >= (unsigned char)'A' &&
            right_ch <= (unsigned char)'Z') {
            right_ch = (unsigned char)(right_ch - (unsigned char)'A' +
                                       (unsigned char)'a');
        }
        if (left_ch != right_ch) {
            return false;
        }
    }

    return true;
}

/*
 * Validate strict, canonical Base64 without retaining or exposing the
 * decoded value. This field is explicitly for non-secret data only.
 */
static bool
validate_nonsecret_base64(const char *encoded)
{
    size_t encoded_length;
    size_t padding = 0U;
    size_t i;
    unsigned char decoded[CONFIG_MAX_BASE64_DECODED + 3U];
    unsigned char reencoded[((CONFIG_MAX_BASE64_DECODED + 2U) / 3U) * 4U + 1U];
    int decoded_length;
    size_t actual_decoded_length;
    int reencoded_length;

    if (encoded == NULL) {
        return true;
    }

    encoded_length = strnlen(encoded, CONFIG_MAX_BASE64_LENGTH + 1U);
    if (encoded_length == 0U ||
        encoded_length > CONFIG_MAX_BASE64_LENGTH ||
        encoded_length % 4U != 0U) {
        return false;
    }

    for (i = 0U; i < encoded_length; ++i) {
        unsigned char ch = (unsigned char)encoded[i];

        if (ch == (unsigned char)'=') {
            if (i < encoded_length - 2U) {
                return false;
            }
            ++padding;
        } else {
            bool valid_character =
                (ch >= (unsigned char)'A' && ch <= (unsigned char)'Z') ||
                (ch >= (unsigned char)'a' && ch <= (unsigned char)'z') ||
                (ch >= (unsigned char)'0' && ch <= (unsigned char)'9') ||
                ch == (unsigned char)'+' || ch == (unsigned char)'/';

            if (!valid_character || padding != 0U) {
                return false;
            }
        }
    }

    if (padding > 2U) {
        return false;
    }

    decoded_length = EVP_DecodeBlock(decoded,
                                     (const unsigned char *)encoded,
                                     (int)encoded_length);
    if (decoded_length < 0 || (size_t)decoded_length < padding) {
        return false;
    }

    actual_decoded_length = (size_t)decoded_length - padding;
    if (actual_decoded_length == 0U ||
        actual_decoded_length > CONFIG_MAX_BASE64_DECODED) {
        return false;
    }

    reencoded_length = EVP_EncodeBlock(reencoded, decoded,
                                       (int)actual_decoded_length);
    if (reencoded_length < 0 ||
        (size_t)reencoded_length != encoded_length ||
        memcmp(reencoded, encoded, encoded_length) != 0) {
        return false;
    }

    return true;
}

enum config_validation_result
validate_config(const struct service_config *config,
                const struct validation_policy *policy,
                char *error,
                size_t error_size)
{
    char canonical_target[PATH_MAX];
    bool directory_authorized = false;
    bool extension_authorized = false;
    size_t i;

    if (error != NULL && error_size > 0U) {
        error[0] = '\0';
    }

    if (config == NULL || policy == NULL) {
        set_error(error, error_size, "configuration or policy is missing");
        return CONFIG_INVALID;
    }

    if (config->target_directory == NULL ||
        config->target_directory[0] == '\0') {
        set_error(error, error_size, "target directory is missing or empty");
        return CONFIG_INVALID;
    }

    if (config->extension == NULL || config->extension[0] == '\0') {
        set_error(error, error_size, "extension is missing or empty");
        return CONFIG_INVALID;
    }

    if (policy->authorized_directories == NULL ||
        policy->authorized_directory_count == 0U ||
        policy->authorized_directory_count > CONFIG_MAX_PATHS) {
        set_error(error, error_size, "authorized directory policy is invalid");
        return CONFIG_INVALID;
    }

    if (policy->allowed_extensions == NULL ||
        policy->allowed_extension_count == 0U ||
        policy->allowed_extension_count > CONFIG_MAX_EXTENSIONS) {
        set_error(error, error_size, "extension allowlist is invalid");
        return CONFIG_INVALID;
    }

    if (!canonicalize_directory(config->target_directory,
                                canonical_target)) {
        set_error(error, error_size,
                  "target directory is malformed, inaccessible, or contains a symbolic link");
        return CONFIG_INVALID;
    }

    for (i = 0U; i < policy->authorized_directory_count; ++i) {
        char canonical_authorized[PATH_MAX];

        if (policy->authorized_directories[i] == NULL ||
            policy->authorized_directories[i][0] == '\0' ||
            !canonicalize_directory(policy->authorized_directories[i],
                                    canonical_authorized)) {
            set_error(error, error_size,
                      "authorized directory policy contains an invalid directory");
            return CONFIG_INVALID;
        }

        if (is_within_directory(canonical_authorized, canonical_target)) {
            directory_authorized = true;
        }
    }

    if (!directory_authorized) {
        set_error(error, error_size,
                  "target directory is not explicitly authorized");
        return CONFIG_INVALID;
    }

    if (!is_valid_extension(config->extension)) {
        set_error(error, error_size, "extension is malformed");
        return CONFIG_INVALID;
    }

    for (i = 0U; i < policy->allowed_extension_count; ++i) {
        const char *allowed = policy->allowed_extensions[i];

        if (!is_valid_extension(allowed)) {
            set_error(error, error_size,
                      "extension allowlist contains a malformed entry");
            return CONFIG_INVALID;
        }

        if (extensions_equal_case_insensitive(config->extension, allowed)) {
            extension_authorized = true;
        }
    }

    if (!extension_authorized) {
        set_error(error, error_size,
                  "extension is not present in the allowlist");
        return CONFIG_INVALID;
    }

    if (config->base64_nonsecret != NULL &&
        !validate_nonsecret_base64(config->base64_nonsecret)) {
        set_error(error, error_size,
                  "non-secret Base64 field is malformed or outside size limits");
        return CONFIG_INVALID;
    }

    return CONFIG_VALID;
}

#ifdef VALIDATE_CONFIG_TEST_MAIN

#include <assert.h>
#include <dirent.h>
#include <stdint.h>

static void
write_test_file(const char *path, const char *contents)
{
    FILE *file = fopen(path, "wb");
    assert(file != NULL);
    assert(fwrite(contents, 1U, strlen(contents), file) == strlen(contents));
    assert(fclose(file) == 0);
}

static void
read_test_file(const char *path, char *buffer, size_t buffer_size)
{
    FILE *file = fopen(path, "rb");
    size_t count;

    assert(file != NULL);
    count = fread(buffer, 1U, buffer_size - 1U, file);
    assert(!ferror(file));
    buffer[count] = '\0';
    assert(fclose(file) == 0);
}

static void
assert_file_unchanged(const char *path, const struct stat *before,
                      const char *expected_contents)
{
    struct stat after;
    char contents[256];

    assert(stat(path, &after) == 0);
    assert(before->st_dev == after.st_dev);
    assert(before->st_ino == after.st_ino);
    assert(before->st_size == after.st_size);
    assert(before->st_mtime == after.st_mtime);
    assert(before->st_ctime == after.st_ctime);
    read_test_file(path, contents, sizeof(contents));
    assert(strcmp(contents, expected_contents) == 0);
}

static void
run_config_validation_tests(void)
{
    char temporary_root[] = "/tmp/validate-config-test-XXXXXX";
    char authorized[PATH_MAX];
    char nested[PATH_MAX];
    char outside[PATH_MAX];
    char file_path[PATH_MAX];
    char symlink_path[PATH_MAX];
    char traversal_path[PATH_MAX];
    char error[256];
    struct stat file_before;
    struct service_config config;
    const char *authorized_directories[1];
    const char *allowed_extensions[] = {".txt", ".dat"};
    struct validation_policy policy;
    char *root;

    root = mkdtemp(temporary_root);
    assert(root != NULL);

    assert(snprintf(authorized, sizeof(authorized), "%s/allowed", root) > 0);
    assert(snprintf(nested, sizeof(nested), "%s/allowed/nested", root) > 0);
    assert(snprintf(outside, sizeof(outside), "%s/outside", root) > 0);
    assert(snprintf(file_path, sizeof(file_path), "%s/allowed/nested/item.txt",
                    root) > 0);
    assert(snprintf(symlink_path, sizeof(symlink_path),
                    "%s/allowed/link", root) > 0);
    assert(snprintf(traversal_path, sizeof(traversal_path),
                    "%s/allowed/../outside", root) > 0);

    assert(mkdir(authorized, 0700) == 0);
    assert(mkdir(nested, 0700) == 0);
    assert(mkdir(outside, 0700) == 0);
    write_test_file(file_path, "unchanged test data\n");
    assert(stat(file_path, &file_before) == 0);
    assert(symlink(outside, symlink_path) == 0);

    authorized_directories[0] = authorized;
    policy.authorized_directories = authorized_directories;
    policy.authorized_directory_count = 1U;
    policy.allowed_extensions = allowed_extensions;
    policy.allowed_extension_count =
        sizeof(allowed_extensions) / sizeof(allowed_extensions[0]);

    config.target_directory = nested;
    config.extension = ".TXT";
    config.base64_nonsecret = "dGVzdA==";
    assert(validate_config(&config, &policy, error, sizeof(error)) ==
           CONFIG_VALID);
    assert(error[0] == '\0');
    assert_file_unchanged(file_path, &file_before, "unchanged test data\n");

    config.target_directory = "";
    assert(validate_config(&config, &policy, error, sizeof(error)) ==
           CONFIG_INVALID);
    assert(error[0] != '\0');

    config.target_directory = NULL;
    assert(validate_config(&config, &policy, error, sizeof(error)) ==
           CONFIG_INVALID);

    config.target_directory = traversal_path;
    assert(validate_config(&config, &policy, error, sizeof(error)) ==
           CONFIG_INVALID);

    config.target_directory = symlink_path;
    assert(validate_config(&config, &policy, error, sizeof(error)) ==
           CONFIG_INVALID);

    config.target_directory = outside;
    assert(validate_config(&config, &policy, error, sizeof(error)) ==
           CONFIG_INVALID);

    config.target_directory = nested;
    config.extension = "";
    assert(validate_config(&config, &policy, error, sizeof(error)) ==
           CONFIG_INVALID);

    config.extension = "txt";
    assert(validate_config(&config, &policy, error, sizeof(error)) ==
           CONFIG_INVALID);

    config.extension = ".exe";
    assert(validate_config(&config, &policy, error, sizeof(error)) ==
           CONFIG_INVALID);

    config.extension = ".txt";
    config.base64_nonsecret = "not base64!";
    assert(validate_config(&config, &policy, error, sizeof(error)) ==
           CONFIG_INVALID);

    config.base64_nonsecret = "A===";
    assert(validate_config(&config, &policy, error, sizeof(error)) ==
           CONFIG_INVALID);

    config.base64_nonsecret = "";
    assert(validate_config(&config, &policy, error, sizeof(error)) ==
           CONFIG_INVALID);

    config.base64_nonsecret = NULL;
    assert(validate_config(&config, &policy, error, sizeof(error)) ==
           CONFIG_VALID);
    assert_file_unchanged(file_path, &file_before, "unchanged test data\n");

    /*
     * validate_config contains no networking calls and opens directories only
     * for read-only inspection. These assertions check that its validation
     * calls neither altered nor removed the test file.
     */
    assert(access(file_path, F_OK) == 0);
    assert_file_unchanged(file_path, &file_before, "unchanged test data\n");

    assert(unlink(symlink_path) == 0);
    assert(unlink(file_path) == 0);
    assert(rmdir(nested) == 0);
    assert(rmdir(authorized) == 0);
    assert(rmdir(outside) == 0);
    assert(rmdir(root) == 0);
}

int
main(void)
{
    run_config_validation_tests();
    return 0;
}

#endif