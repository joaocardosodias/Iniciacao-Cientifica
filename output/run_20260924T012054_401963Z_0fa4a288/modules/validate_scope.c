#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static void validate_scope_set_error(char *error, size_t error_size,
                                     const char *message)
{
    if (error != NULL && error_size > 0) {
        (void)snprintf(error, error_size, "%s", message);
    }
}

static void validate_scope_set_errno_error(char *error, size_t error_size,
                                           const char *operation, int errnum)
{
    if (error != NULL && error_size > 0) {
        (void)snprintf(error, error_size, "%s: %s", operation,
                       strerror(errnum));
    }
}

/*
 * Returns 0 on success and -1 on failure.
 * On success, resolved_path contains the canonical absolute directory path.
 * On failure, resolved_path is left empty when a writable output buffer was
 * supplied. The caller owns the output buffer.
 */
int validate_scope(const char *configured_scope,
                   char *resolved_path, size_t resolved_path_size,
                   char *error, size_t error_size)
{
    const char *home;
    char *candidate = NULL;
    char *canonical = NULL;
    size_t scope_length;
    size_t home_length;
    size_t separator_length;
    size_t candidate_length;
    struct stat st;
    int saved_errno;

    if (resolved_path != NULL && resolved_path_size > 0) {
        resolved_path[0] = '\0';
    }
    if (error != NULL && error_size > 0) {
        error[0] = '\0';
    }

    if (resolved_path == NULL || resolved_path_size == 0) {
        validate_scope_set_error(error, error_size,
                                 "resolved path buffer is invalid");
        return -1;
    }
    if (configured_scope == NULL || configured_scope[0] == '\0') {
        validate_scope_set_error(error, error_size,
                                 "test directory configuration is missing or empty");
        return -1;
    }

    scope_length = strlen(configured_scope);
    if (configured_scope[0] == '/') {
        candidate = strdup(configured_scope);
        if (candidate == NULL) {
            saved_errno = errno;
            validate_scope_set_errno_error(error, error_size,
                                           "unable to allocate test directory path",
                                           saved_errno);
            return -1;
        }
    } else {
        home = getenv("HOME");
        if (home == NULL || home[0] == '\0') {
            validate_scope_set_error(error, error_size,
                                     "HOME must be set and non-empty for a relative test directory");
            return -1;
        }

        home_length = strlen(home);
        separator_length =
            (home_length > 0 && home[home_length - 1] == '/') ? 0 : 1;

        if (home_length > SIZE_MAX - separator_length ||
            home_length + separator_length > SIZE_MAX - scope_length - 1) {
            validate_scope_set_error(error, error_size,
                                     "test directory path is too long");
            return -1;
        }

        candidate_length = home_length + separator_length + scope_length + 1;
        candidate = malloc(candidate_length);
        if (candidate == NULL) {
            saved_errno = errno;
            validate_scope_set_errno_error(error, error_size,
                                           "unable to allocate test directory path",
                                           saved_errno);
            return -1;
        }

        memcpy(candidate, home, home_length);
        if (separator_length != 0) {
            candidate[home_length] = '/';
        }
        memcpy(candidate + home_length + separator_length,
               configured_scope, scope_length);
        candidate[home_length + separator_length + scope_length] = '\0';
    }

    canonical = realpath(candidate, NULL);
    if (canonical == NULL) {
        saved_errno = errno;
        validate_scope_set_errno_error(error, error_size,
                                       "unable to resolve test directory",
                                       saved_errno);
        free(candidate);
        return -1;
    }
    free(candidate);

    if (stat(canonical, &st) != 0) {
        saved_errno = errno;
        validate_scope_set_errno_error(error, error_size,
                                       "unable to access test directory",
                                       saved_errno);
        free(canonical);
        return -1;
    }
    if (!S_ISDIR(st.st_mode)) {
        validate_scope_set_error(error, error_size,
                                 "test directory path does not name a directory");
        free(canonical);
        return -1;
    }

    candidate_length = strlen(canonical);
    if (candidate_length >= resolved_path_size) {
        validate_scope_set_error(error, error_size,
                                 "resolved test directory path does not fit in the output buffer");
        free(canonical);
        return -1;
    }

    memcpy(resolved_path, canonical, candidate_length + 1);
    free(canonical);
    return 0;
}

#ifdef VALIDATE_SCOPE_TEST
#include <assert.h>

int main(void)
{
    char temporary[] = "/tmp/validate-scope-test-XXXXXX";
    char directory[PATH_MAX];
    char file_path[PATH_MAX];
    char output[PATH_MAX];
    char error[256];
    char *root;
    char *expected;
    char *saved_home = NULL;
    const char *old_home;
    int had_home;

    old_home = getenv("HOME");
    had_home = old_home != NULL;
    if (had_home) {
        saved_home = strdup(old_home);
        assert(saved_home != NULL);
    }

    root = mkdtemp(temporary);
    assert(root != NULL);
    assert(snprintf(directory, sizeof(directory), "%s/tests", root) <
           (int)sizeof(directory));
    assert(mkdir(directory, 0700) == 0);
    assert(snprintf(file_path, sizeof(file_path), "%s/not-a-directory", root) <
           (int)sizeof(file_path));

    FILE *file = fopen(file_path, "w");
    assert(file != NULL);
    assert(fclose(file) == 0);

    assert(validate_scope(NULL, output, sizeof(output), error, sizeof(error)) ==
           -1);
    assert(output[0] == '\0');
    assert(validate_scope("", output, sizeof(output), error, sizeof(error)) ==
           -1);
    assert(output[0] == '\0');

    assert(setenv("HOME", root, 1) == 0);
    expected = realpath(directory, NULL);
    assert(expected != NULL);
    assert(validate_scope("tests", output, sizeof(output), error,
                          sizeof(error)) == 0);
    assert(strcmp(output, expected) == 0);
    assert(validate_scope(directory, output, sizeof(output), error,
                          sizeof(error)) == 0);
    assert(strcmp(output, expected) == 0);
    free(expected);

    assert(unsetenv("HOME") == 0);
    assert(validate_scope("tests", output, sizeof(output), error,
                          sizeof(error)) == -1);
    assert(output[0] == '\0');

    assert(setenv("HOME", root, 1) == 0);
    assert(validate_scope(file_path, output, sizeof(output), error,
                          sizeof(error)) == -1);
    assert(output[0] == '\0');

    assert(validate_scope("missing-directory", output, sizeof(output), error,
                          sizeof(error)) == -1);
    assert(output[0] == '\0');

    assert(unlink(file_path) == 0);
    assert(rmdir(directory) == 0);
    assert(rmdir(root) == 0);

    if (had_home) {
        assert(setenv("HOME", saved_home, 1) == 0);
    } else {
        assert(unsetenv("HOME") == 0);
    }
    free(saved_home);
    return 0;
}
#endif