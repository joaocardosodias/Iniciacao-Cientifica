#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

 

 
static int
is_canonical_absolute_path(const char *path)
{
    const char *component;
    const char *p;

    if (path == NULL || path[0] != '/' || path[1] == '\0')
        return 0;

    component = path + 1;
    for (p = component; ; ++p) {
        if (*p == '/' || *p == '\0') {
            size_t length = (size_t)(p - component);

            if (length == 0)
                return 0;
            if ((length == 1 && component[0] == '.') ||
                (length == 2 && component[0] == '.' &&
                 component[1] == '.'))
                return 0;

            if (*p == '\0')
                return 1;

            component = p + 1;
        }
    }
}

static int
fail_with_errno(int error, int directory_fd, int file_fd)
{
    if (file_fd >= 0)
        (void)close(file_fd);
    if (directory_fd >= 0)
        (void)close(directory_fd);
    errno = error;
    return -1;
}

int
validate_scope(const char *requested_path,
               const char *const *allowlist,
               size_t allowlist_count,
               int *out_fd)
{
    size_t i;
    int directory_fd = -1;
    int file_fd = -1;
    const char *component;
    const char *p;

    if (out_fd == NULL) {
        errno = EINVAL;
        return -1;
    }
    *out_fd = -1;

    if (!is_canonical_absolute_path(requested_path)) {
        errno = EINVAL;
        return -1;
    }

    if (allowlist_count == 0) {
        errno = EACCES;
        return -1;
    }
    if (allowlist == NULL) {
        errno = EINVAL;
        return -1;
    }

    for (i = 0; i < allowlist_count; ++i) {
        if (!is_canonical_absolute_path(allowlist[i])) {
            errno = EINVAL;
            return -1;
        }
    }

    for (i = 0; i < allowlist_count; ++i) {
        if (strcmp(requested_path, allowlist[i]) == 0)
            break;
    }
    if (i == allowlist_count) {
        errno = EACCES;
        return -1;
    }

    directory_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (directory_fd < 0)
        return -1;

    component = requested_path + 1;
    for (p = component; ; ++p) {
        size_t length;
        char *name;
        int is_final;
        int next_fd;

        if (*p != '/' && *p != '\0')
            continue;

        length = (size_t)(p - component);
        is_final = (*p == '\0');
        name = malloc(length + 1);
        if (name == NULL)
            return fail_with_errno(errno, directory_fd, -1);

        memcpy(name, component, length);
        name[length] = '\0';

        if (is_final) {
            next_fd = openat(directory_fd, name,
                             O_RDONLY | O_NOFOLLOW | O_CLOEXEC | O_NONBLOCK);
        } else {
            next_fd = openat(directory_fd, name,
                             O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
        }

        {
            int saved_errno = errno;
            free(name);
            if (next_fd < 0)
                return fail_with_errno(saved_errno, directory_fd, -1);
        }

        if (is_final) {
            struct stat st;

            file_fd = next_fd;
            if (fstat(file_fd, &st) < 0)
                return fail_with_errno(errno, directory_fd, file_fd);
            if (!S_ISREG(st.st_mode))
                return fail_with_errno(EACCES, directory_fd, file_fd);

            (void)close(directory_fd);
            *out_fd = file_fd;
            return 0;
        }

        (void)close(directory_fd);
        directory_fd = next_fd;
        component = p + 1;
    }
}

#ifndef VALIDATE_SCOPE_NO_TEST_MAIN

static int
write_test_file(const char *path, const char *contents)
{
    int fd;
    size_t length = strlen(contents);
    size_t written = 0;

    fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd < 0)
        return -1;

    while (written < length) {
        ssize_t result = write(fd, contents + written, length - written);
        if (result < 0) {
            int saved_errno = errno;
            (void)close(fd);
            errno = saved_errno;
            return -1;
        }
        written += (size_t)result;
    }

    if (close(fd) < 0)
        return -1;
    return 0;
}

static int
file_matches(const char *path, const char *expected)
{
    char buffer[128];
    size_t used = 0;
    int fd = open(path, O_RDONLY | O_CLOEXEC);

    if (fd < 0)
        return 0;

    while (used < sizeof(buffer)) {
        ssize_t result = read(fd, buffer + used, sizeof(buffer) - used);
        if (result < 0) {
            (void)close(fd);
            return 0;
        }
        if (result == 0)
            break;
        used += (size_t)result;
    }

    if (close(fd) < 0)
        return 0;

    return used == strlen(expected) &&
           memcmp(buffer, expected, used) == 0;
}

static int
expect_failure(const char *path, const char *const *allowlist,
               size_t allowlist_count)
{
    int fd = 99;

    if (validate_scope(path, allowlist, allowlist_count, &fd) != -1)
        return 0;
    return fd == -1 && errno != 0;
}

static int
test_validate_scope(void)
{
    char template[] = "/tmp/validate-scope-test-XXXXXX";
    char *directory;
    char source[4096];
    char other[4096];
    char subdirectory[4096];
    char directory_path[4096];
    char link_path[4096];
    char file_link_path[4096];
    const char original[] = "source remains unchanged\n";
    const char other_contents[] = "not authorized\n";
    const char *allowlist[1];
    const char *invalid_allowlist[1];
    int fd = -1;
    int flags;
    int result = 1;

    directory = mkdtemp(template);
    if (directory == NULL) {
        perror("mkdtemp");
        return 1;
    }

    if (snprintf(source, sizeof(source), "%s/source.txt", directory) >=
            (int)sizeof(source) ||
        snprintf(other, sizeof(other), "%s/other.txt", directory) >=
            (int)sizeof(other) ||
        snprintf(subdirectory, sizeof(subdirectory), "%s/sub", directory) >=
            (int)sizeof(subdirectory) ||
        snprintf(directory_path, sizeof(directory_path), "%s/folder", directory) >=
            (int)sizeof(directory_path) ||
        snprintf(link_path, sizeof(link_path), "%s/link", directory) >=
            (int)sizeof(link_path) ||
        snprintf(file_link_path, sizeof(file_link_path), "%s/file-link", directory) >=
            (int)sizeof(file_link_path)) {
        fprintf(stderr, "test path too long\n");
        goto cleanup;
    }

    if (write_test_file(source, original) < 0 ||
        write_test_file(other, other_contents) < 0 ||
        mkdir(subdirectory, 0700) < 0 ||
        mkdir(directory_path, 0700) < 0 ||
        symlink(subdirectory, link_path) < 0 ||
        symlink(source, file_link_path) < 0) {
        perror("creating test fixtures");
        goto cleanup;
    }

    allowlist[0] = source;

    if (validate_scope(source, allowlist, 1, &fd) != 0) {
        perror("authorized file rejected");
        goto cleanup;
    }

    flags = fcntl(fd, F_GETFL);
    if (flags < 0 || (flags & O_ACCMODE) != O_RDONLY) {
        fprintf(stderr, "returned descriptor is not read-only\n");
        (void)close(fd);
        fd = -1;
        goto cleanup;
    }

    errno = 0;
    if (write(fd, "x", 1) != -1 || errno != EBADF) {
        fprintf(stderr, "write unexpectedly succeeded on read-only descriptor\n");
        (void)close(fd);
        fd = -1;
        goto cleanup;
    }

    if (close(fd) < 0) {
        perror("closing returned descriptor");
        fd = -1;
        goto cleanup;
    }
    fd = -1;

    if (!file_matches(source, original)) {
        fprintf(stderr, "source file contents changed\n");
        goto cleanup;
    }

    if (!expect_failure(other, allowlist, 1)) {
        fprintf(stderr, "unauthorized file was accepted\n");
        goto cleanup;
    }
    if (!expect_failure(source, NULL, 0)) {
        fprintf(stderr, "empty allowlist did not deny access\n");
        goto cleanup;
    }

    invalid_allowlist[0] = "/tmp/../invalid";
    if (!expect_failure(source, invalid_allowlist, 1)) {
        fprintf(stderr, "invalid allowlist entry was accepted\n");
        goto cleanup;
    }
    if (!expect_failure(source, NULL, 1)) {
        fprintf(stderr, "null allowlist was accepted\n");
        goto cleanup;
    }

    if (!expect_failure("relative/path", allowlist, 1)) {
        fprintf(stderr, "relative path was accepted\n");
        goto cleanup;
    }
    if (!expect_failure("/tmp/./file", allowlist, 1) ||
        !expect_failure("/tmp/../file", allowlist, 1) ||
        !expect_failure("/tmp
        !expect_failure("/tmp/", allowlist, 1)) {
        fprintf(stderr, "noncanonical path was accepted\n");
        goto cleanup;
    }
    if (!expect_failure("/definitely-not-present-validate-scope", 
                        (const char *const[]){"/definitely-not-present-validate-scope"},
                        1)) {
        fprintf(stderr, "nonexistent file was accepted\n");
        goto cleanup;
    }
    if (!expect_failure(directory_path,
                        (const char *const[]){directory_path}, 1)) {
        fprintf(stderr, "directory was accepted\n");
        goto cleanup;
    }

    {
        char symlinked_file[4096];
        if (snprintf(symlinked_file, sizeof(symlinked_file),
                     "%s/source.txt", link_path) >= (int)sizeof(symlinked_file)) {
            fprintf(stderr, "symlink test path too long\n");
            goto cleanup;
        }
        if (!expect_failure(symlinked_file,
                            (const char *const[]){symlinked_file}, 1)) {
            fprintf(stderr, "path through directory symlink was accepted\n");
            goto cleanup;
        }
    }

    if (!expect_failure(file_link_path,
                        (const char *const[]){file_link_path}, 1)) {
        fprintf(stderr, "final symlink was accepted\n");
        goto cleanup;
    }

    if (!file_matches(source, original)) {
        fprintf(stderr, "source file contents changed during tests\n");
        goto cleanup;
    }

    result = 0;

cleanup:
    if (fd >= 0)
        (void)close(fd);
    (void)unlink(file_link_path);
    (void)unlink(link_path);
    (void)rmdir(directory_path);
    (void)rmdir(subdirectory);
    (void)unlink(other);
    (void)unlink(source);
    (void)rmdir(directory);

    if (result == 0)
        puts("validate_scope tests passed");
    return result;
}
#endif