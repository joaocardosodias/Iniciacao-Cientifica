#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Preserve a set of regular-file sources by copying each one to its paired
 * destination. Sources are opened read-only and are never renamed, removed,
 * overwritten, chmod'd, or otherwise intentionally modified. Destination
 * files must not already exist; each is created exclusively.
 *
 * Parameters:
 *   sources      Array of source path strings.
 *   destinations Array of destination path strings, paired by index with
 *                sources.
 *   count        Number of paths in each array.
 *
 * Returns 0 if every copy succeeds, or -1 on invalid input, a path conflict,
 * or an I/O/metadata error. On failure, errno identifies the error. A
 * destination being written when an error occurs is removed when it can be
 * safely identified as the file created by this call. Earlier successful
 * destinations are not rolled back. Source contents and source directory
 * entries are never changed.
 *
 * Source atime is protected where supported by opening with O_NOATIME. If
 * that cannot be done, the operation fails rather than risk changing it.
 */
static int preserve_one_source(const char *source, const char *destination);

int preserve_sources(const char *const sources[],
                     const char *const destinations[],
                     size_t count)
{
    size_t i;

    if (count != 0 && (sources == NULL || destinations == NULL)) {
        errno = EINVAL;
        return -1;
    }

    for (i = 0; i < count; ++i) {
        if (sources[i] == NULL || destinations[i] == NULL ||
            sources[i][0] == '\0' || destinations[i][0] == '\0') {
            errno = EINVAL;
            return -1;
        }
        if (preserve_one_source(sources[i], destinations[i]) != 0)
            return -1;
    }

    return 0;
}

static int same_file_identity(const struct stat *a, const struct stat *b)
{
    return a->st_dev == b->st_dev && a->st_ino == b->st_ino;
}

static void remove_created_destination(int dirfd, const char *basename,
                                       const struct stat *created_stat)
{
    struct stat current;

    if (fstatat(dirfd, basename, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
        same_file_identity(&current, created_stat)) {
        (void)unlinkat(dirfd, basename, 0);
    }
}

static int split_destination(const char *destination, char **parent_out,
                             char **basename_out)
{
    const char *slash;
    size_t parent_len;
    char *parent;
    char *basename;

    slash = strrchr(destination, '/');
    if (slash == NULL) {
        parent = strdup(".");
        basename = strdup(destination);
    } else {
        basename = strdup(slash + 1);
        if (slash == destination) {
            parent = strdup("/");
        } else {
            parent_len = (size_t)(slash - destination);
            parent = malloc(parent_len + 1);
            if (parent != NULL) {
                memcpy(parent, destination, parent_len);
                parent[parent_len] = '\0';
            }
        }
    }

    if (parent == NULL || basename == NULL) {
        free(parent);
        free(basename);
        errno = ENOMEM;
        return -1;
    }

    if (basename[0] == '\0' || strcmp(basename, ".") == 0 ||
        strcmp(basename, "..") == 0) {
        free(parent);
        free(basename);
        errno = EINVAL;
        return -1;
    }

    *parent_out = parent;
    *basename_out = basename;
    return 0;
}

static int preserve_one_source(const char *source, const char *destination)
{
    int source_fd = -1;
    int destination_fd = -1;
    int destination_dir_fd = -1;
    int result = -1;
    int saved_errno = 0;
    int created = 0;
    char *canonical_source = NULL;
    char *parent = NULL;
    char *canonical_parent = NULL;
    char *basename = NULL;
    char *canonical_destination = NULL;
    struct stat source_stat;
    struct stat canonical_source_stat;
    struct stat parent_stat;
    struct stat opened_parent_stat;
    struct stat destination_stat;
    struct stat created_stat;
    struct stat check_stat;
    struct timespec times[2];
    char buffer[65536];
    ssize_t bytes_read;
    size_t offset;
    int flags;

    canonical_source = realpath(source, NULL);
    if (canonical_source == NULL)
        goto done;

    flags = O_RDONLY | O_CLOEXEC;
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef O_NOATIME
    flags |= O_NOATIME;
#else
    errno = ENOTSUP;
    goto done;
#endif

    source_fd = open(source, flags);
    if (source_fd < 0)
        goto done;

    if (fstat(source_fd, &source_stat) != 0)
        goto done;
    if (!S_ISREG(source_stat.st_mode)) {
        errno = EINVAL;
        goto done;
    }

    if (stat(canonical_source, &canonical_source_stat) != 0)
        goto done;
    if (!same_file_identity(&source_stat, &canonical_source_stat)) {
        errno = ESTALE;
        goto done;
    }

    if (split_destination(destination, &parent, &basename) != 0)
        goto done;

    canonical_parent = realpath(parent, NULL);
    if (canonical_parent == NULL)
        goto done;

    if (stat(canonical_parent, &parent_stat) != 0)
        goto done;
    if (!S_ISDIR(parent_stat.st_mode)) {
        errno = ENOTDIR;
        goto done;
    }

    destination_dir_fd = open(canonical_parent, O_RDONLY | O_DIRECTORY |
                                                   O_CLOEXEC);
    if (destination_dir_fd < 0)
        goto done;

    if (fstat(destination_dir_fd, &opened_parent_stat) != 0)
        goto done;
    if (!same_file_identity(&parent_stat, &opened_parent_stat)) {
        errno = ESTALE;
        goto done;
    }

    {
        size_t parent_len = strlen(canonical_parent);
        size_t basename_len = strlen(basename);
        size_t needed;

        if (parent_len > SIZE_MAX - basename_len - 2) {
            errno = ENAMETOOLONG;
            goto done;
        }
        needed = parent_len + basename_len + 2;
        canonical_destination = malloc(needed);
        if (canonical_destination == NULL) {
            errno = ENOMEM;
            goto done;
        }
        if (snprintf(canonical_destination, needed, "%s%s%s",
                     canonical_parent,
                     strcmp(canonical_parent, "/") == 0 ? "" : "/",
                     basename) < 0) {
            errno = EINVAL;
            goto done;
        }
    }

    if (strcmp(canonical_source, canonical_destination) == 0) {
        errno = EINVAL;
        goto done;
    }

    if (fstatat(destination_dir_fd, basename, &destination_stat,
                AT_SYMLINK_NOFOLLOW) == 0) {
        if (same_file_identity(&destination_stat, &source_stat))
            errno = EINVAL;
        else
            errno = EEXIST;
        goto done;
    }
    if (errno != ENOENT)
        goto done;

    destination_fd = openat(destination_dir_fd, basename,
                            O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC
#ifdef O_NOFOLLOW
                                | O_NOFOLLOW
#endif
                            ,
                            0600);
    if (destination_fd < 0)
        goto done;
    created = 1;

    if (fstat(destination_fd, &created_stat) != 0)
        goto done;
    if (same_file_identity(&created_stat, &source_stat)) {
        errno = EINVAL;
        created = 0;
        goto done;
    }

    for (;;) {
        bytes_read = read(source_fd, buffer, sizeof(buffer));
        if (bytes_read == 0)
            break;
        if (bytes_read < 0) {
            if (errno == EINTR)
                continue;
            goto done;
        }

        offset = 0;
        while (offset < (size_t)bytes_read) {
            ssize_t bytes_written =
                write(destination_fd, buffer + offset,
                      (size_t)bytes_read - offset);
            if (bytes_written < 0) {
                if (errno == EINTR)
                    continue;
                goto done;
            }
            if (bytes_written == 0) {
                errno = EIO;
                goto done;
            }
            offset += (size_t)bytes_written;
        }
    }

    if (fchmod(destination_fd, source_stat.st_mode & 07777) != 0)
        goto done;

    times[0] = source_stat.st_atim;
    times[1] = source_stat.st_mtim;
    if (futimens(destination_fd, times) != 0)
        goto done;

    if (fsync(destination_fd) != 0)
        goto done;

    if (fstat(destination_fd, &created_stat) != 0)
        goto done;

    if (close(destination_fd) != 0) {
        destination_fd = -1;
        goto done;
    }
    destination_fd = -1;

    if (close(source_fd) != 0) {
        source_fd = -1;
        goto done;
    }
    source_fd = -1;

    result = 0;

done:
    if (result != 0)
        saved_errno = errno != 0 ? errno : EIO;

    if (destination_fd >= 0)
        (void)close(destination_fd);
    if (source_fd >= 0)
        (void)close(source_fd);

    if (result != 0 && created && destination_dir_fd >= 0) {
        if (fstatat(destination_dir_fd, basename, &check_stat,
                    AT_SYMLINK_NOFOLLOW) == 0 &&
            same_file_identity(&check_stat, &created_stat)) {
            (void)unlinkat(destination_dir_fd, basename, 0);
        }
    }

    if (destination_dir_fd >= 0)
        (void)close(destination_dir_fd);

    free(canonical_source);
    free(parent);
    free(canonical_parent);
    free(basename);
    free(canonical_destination);

    if (result != 0)
        errno = saved_errno;
    return result;
}

#ifdef PRESERVE_SOURCES_TEST
#include <dirent.h>
#include <stdint.h>

static int write_file(const char *path, const char *data)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    size_t length = strlen(data);
    size_t offset = 0;

    if (fd < 0)
        return -1;
    while (offset < length) {
        ssize_t written = write(fd, data + offset, length - offset);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            (void)close(fd);
            return -1;
        }
        if (written == 0) {
            (void)close(fd);
            errno = EIO;
            return -1;
        }
        offset += (size_t)written;
    }
    return close(fd);
}

static int file_equals(const char *path, const char *expected)
{
    int fd;
    char buffer[4096];
    size_t expected_length = strlen(expected);
    size_t total = 0;
    ssize_t n;

    fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return 0;

    while ((n = read(fd, buffer, sizeof(buffer))) != 0) {
        size_t i;
        if (n < 0) {
            if (errno == EINTR)
                continue;
            (void)close(fd);
            return 0;
        }
        for (i = 0; i < (size_t)n; ++i) {
            if (total >= expected_length ||
                buffer[i] != expected[total]) {
                (void)close(fd);
                return 0;
            }
            ++total;
        }
    }

    if (close(fd) != 0)
        return 0;
    return total == expected_length;
}

static int file_exists(const char *path)
{
    struct stat st;
    return lstat(path, &st) == 0;
}

static int make_path(char *buffer, size_t size, const char *directory,
                     const char *name)
{
    int n = snprintf(buffer, size, "%s/%s", directory, name);
    return n >= 0 && (size_t)n < size ? 0 : -1;
}

static int test_preserve_sources(void)
{
    char template[] = "/tmp/preserve-sources-test-XXXXXX";
    char *directory;
    char source[PATH_MAX];
    char destination[PATH_MAX];
    char existing[PATH_MAX];
    char missing[PATH_MAX];
    const char *sources[2];
    const char *destinations[2];
    struct stat before;
    struct stat after;
    int failed = 0;

    directory = mkdtemp(template);
    if (directory == NULL)
        return 1;

    if (make_path(source, sizeof(source), directory, "source.txt") != 0 ||
        make_path(destination, sizeof(destination), directory, "copy.txt") != 0 ||
        make_path(existing, sizeof(existing), directory, "existing.txt") != 0 ||
        make_path(missing, sizeof(missing), directory, "missing.txt") != 0)
        return 1;

    if (write_file(source, "immutable source data") != 0 ||
        stat(source, &before) != 0)
        return 1;

    sources[0] = source;
    destinations[0] = destination;
    if (preserve_sources(sources, destinations, 1) != 0 ||
        !file_equals(source, "immutable source data") ||
        !file_equals(destination, "immutable source data") ||
        !file_exists(source) || stat(source, &after) != 0 ||
        !same_file_identity(&before, &after)) {
        failed = 1;
    }

    if (!failed) {
        if (preserve_sources(sources, sources, 1) == 0 ||
            !file_equals(source, "immutable source data") ||
            !file_exists(source))
            failed = 1;
    }

    if (!failed) {
        if (write_file(existing, "keep existing destination") != 0 ||
            stat(source, &before) != 0)
            failed = 1;
        else {
            sources[0] = source;
            destinations[0] = existing;
            if (preserve_sources(sources, destinations, 1) == 0 ||
                !file_equals(source, "immutable source data") ||
                !file_equals(existing, "keep existing destination") ||
                !file_exists(source) || stat(source, &after) != 0 ||
                !same_file_identity(&before, &after))
                failed = 1;
        }
    }

    if (!failed) {
        sources[0] = source;
        sources[1] = missing;
        destinations[0] = destination;
        destinations[1] = existing;
        if (stat(source, &before) != 0 ||
            preserve_sources(sources, destinations, 2) == 0 ||
            !file_equals(source, "immutable source data") ||
            !file_exists(source) || stat(source, &after) != 0 ||
            !same_file_identity(&before, &after))
            failed = 1;
    }

    (void)unlink(destination);
    (void)unlink(existing);
    (void)unlink(source);
    (void)rmdir(directory);

    return failed ? 1 : 0;
}

int main(void)
{
    if (test_preserve_sources() != 0) {
        fprintf(stderr, "preserve_sources tests failed\n");
        return 1;
    }
    puts("preserve_sources tests passed");
    return 0;
}
#endif