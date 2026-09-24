#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <sys/random.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#ifndef O_CLOEXEC
#define O_CLOEXEC 0
#endif

/*
 * Session-key file format, version 1 (all multi-byte integers are big-endian):
 *
 *   Offset  Size  Contents
 *   0       4     Magic bytes "SSKY"
 *   4       2     Format version (1)
 *   6       4     Key length in bytes, unsigned 32-bit integer
 *   10      N     Key bytes, unchanged
 *
 * The file is created with mode 0600 and atomically renamed into place.
 * Returns 0 on success, or -1 on failure with errno set.
 */

#define SESSION_KEY_HEADER_SIZE 10U
#define SESSION_KEY_VERSION 1U

static int
session_key_write_all(int fd, const uint8_t *data, size_t length)
{
    size_t written = 0;

    while (written < length) {
        size_t remaining = length - written;
        size_t chunk = remaining;

        if (chunk > (size_t)SSIZE_MAX)
            chunk = (size_t)SSIZE_MAX;

        ssize_t result = write(fd, data + written, chunk);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (result == 0) {
            errno = EIO;
            return -1;
        }
        written += (size_t)result;
    }

    return 0;
}

static int
session_key_random_bytes(uint8_t *buffer, size_t length)
{
    size_t received = 0;

    while (received < length) {
        ssize_t result = getrandom(buffer + received, length - received, 0);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (result == 0) {
            errno = EIO;
            return -1;
        }
        received += (size_t)result;
    }

    return 0;
}

static void
session_key_remove_temp_if_same(int dirfd, const char *name,
                                dev_t device, ino_t inode, int identity_valid)
{
    struct stat current;

    if (!identity_valid)
        return;

    if (fstatat(dirfd, name, &current, AT_SYMLINK_NOFOLLOW) == 0 &&
        current.st_dev == device && current.st_ino == inode)
        (void)unlinkat(dirfd, name, 0);
}

int
store_session_key(const char *path, const uint8_t *key, size_t key_len)
{
    static const uint8_t magic[4] = { 'S', 'S', 'K', 'Y' };
    char *directory = NULL;
    const char *basename;
    const char *slash;
    int dirfd = -1;
    int tempfd = -1;
    int result = -1;
    int saved_errno = 0;
    char tempname[sizeof(".session-key-") - 1 + 32 + 1];
    uint8_t nonce[16];
    uint8_t header[SESSION_KEY_HEADER_SIZE];
    struct stat destination_stat;
    struct stat temp_stat;
    dev_t temp_device = 0;
    ino_t temp_inode = 0;
    int temp_identity_valid = 0;
    int temp_exists = 0;

    if (path == NULL || key == NULL || key_len == 0 ||
        key_len > UINT32_MAX ||
        key_len > SIZE_MAX - SESSION_KEY_HEADER_SIZE) {
        errno = EINVAL;
        return -1;
    }

    slash = strrchr(path, '/');
    if (slash == NULL) {
        basename = path;
        directory = strdup(".");
    } else {
        basename = slash + 1;
        if (slash == path) {
            directory = strdup("/");
        } else {
            size_t directory_len = (size_t)(slash - path);
            directory = malloc(directory_len + 1);
            if (directory != NULL) {
                memcpy(directory, path, directory_len);
                directory[directory_len] = '\0';
            }
        }
    }

    if (directory == NULL)
        return -1;

    if (basename[0] == '\0' ||
        (basename[0] == '.' && basename[1] == '\0') ||
        (basename[0] == '.' && basename[1] == '.' && basename[2] == '\0')) {
        errno = EINVAL;
        goto done;
    }

    dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd < 0)
        goto done;

    if (fstatat(dirfd, basename, &destination_stat, AT_SYMLINK_NOFOLLOW) == 0) {
        if (S_ISLNK(destination_stat.st_mode)) {
            errno = ELOOP;
            goto done;
        }
        if (!S_ISREG(destination_stat.st_mode)) {
            errno = EINVAL;
            goto done;
        }
    } else if (errno != ENOENT) {
        goto done;
    }

    memcpy(header, magic, sizeof(magic));
    header[4] = 0;
    header[5] = SESSION_KEY_VERSION;
    header[6] = (uint8_t)((uint32_t)key_len >> 24);
    header[7] = (uint8_t)((uint32_t)key_len >> 16);
    header[8] = (uint8_t)((uint32_t)key_len >> 8);
    header[9] = (uint8_t)(uint32_t)key_len;

    for (unsigned int attempt = 0; attempt < 128; ++attempt) {
        static const char hex[] = "0123456789abcdef";
        const char prefix[] = ".session-key-";

        if (session_key_random_bytes(nonce, sizeof(nonce)) < 0)
            goto done;

        memcpy(tempname, prefix, sizeof(prefix) - 1);
        for (size_t i = 0; i < sizeof(nonce); ++i) {
            tempname[sizeof(prefix) - 1 + i * 2] = hex[nonce[i] >> 4];
            tempname[sizeof(prefix) + i * 2] = hex[nonce[i] & 0x0f];
        }
        tempname[sizeof(tempname) - 1] = '\0';

        tempfd = openat(dirfd, tempname,
                        O_WRONLY | O_CREAT | O_EXCL | O_NOFOLLOW | O_CLOEXEC,
                        0600);
        if (tempfd >= 0) {
            temp_exists = 1;
            break;
        }
        if (errno != EEXIST)
            goto done;
    }

    if (tempfd < 0) {
        errno = EEXIST;
        goto done;
    }

    if (fstat(tempfd, &temp_stat) < 0)
        goto done;
    temp_device = temp_stat.st_dev;
    temp_inode = temp_stat.st_ino;
    temp_identity_valid = 1;

    if (!S_ISREG(temp_stat.st_mode) || temp_stat.st_uid != getuid()) {
        errno = EPERM;
        goto done;
    }

    if (fchmod(tempfd, S_IRUSR | S_IWUSR) < 0)
        goto done;

    if (session_key_write_all(tempfd, header, sizeof(header)) < 0 ||
        session_key_write_all(tempfd, key, key_len) < 0)
        goto done;

    if (fsync(tempfd) < 0)
        goto done;

    if (fstat(tempfd, &temp_stat) < 0)
        goto done;
    if (temp_stat.st_uid != getuid() ||
        (temp_stat.st_mode & 07777) != (S_IRUSR | S_IWUSR)) {
        errno = EPERM;
        goto done;
    }

    if (close(tempfd) < 0) {
        tempfd = -1;
        goto done;
    }
    tempfd = -1;

    if (renameat(dirfd, tempname, dirfd, basename) < 0)
        goto done;
    temp_exists = 0;

    if (fsync(dirfd) < 0)
        goto done;

    result = 0;

done:
    saved_errno = errno;

    if (tempfd >= 0)
        (void)close(tempfd);

    if (temp_exists && dirfd >= 0)
        session_key_remove_temp_if_same(dirfd, tempname, temp_device,
                                        temp_inode, temp_identity_valid);

    if (dirfd >= 0)
        (void)close(dirfd);
    free(directory);

    if (result < 0)
        errno = saved_errno;
    return result;
}

#ifdef STORE_SESSION_KEY_TEST

#include <dirent.h>

static int
test_read_file(const char *path, uint8_t *buffer, size_t capacity,
               size_t *length)
{
    int fd = open(path, O_RDONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    size_t used = 0;
    for (;;) {
        if (used == capacity) {
            uint8_t extra;
            ssize_t n = read(fd, &extra, 1);
            if (n < 0 && errno == EINTR)
                continue;
            if (n != 0) {
                int error = n < 0 ? errno : EOVERFLOW;
                (void)close(fd);
                errno = error;
                return -1;
            }
            break;
        }

        ssize_t n = read(fd, buffer + used, capacity - used);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            int error = errno;
            (void)close(fd);
            errno = error;
            return -1;
        }
        if (n == 0)
            break;
        used += (size_t)n;
    }

    if (close(fd) < 0)
        return -1;

    *length = used;
    return 0;
}

static int
test_directory_entry_count(const char *path, size_t *count)
{
    DIR *dir = opendir(path);
    if (dir == NULL)
        return -1;

    size_t entries = 0;
    struct dirent *entry;
    while ((entry = readdir(dir)) != NULL) {
        if (strcmp(entry->d_name, ".") != 0 &&
            strcmp(entry->d_name, "..") != 0)
            ++entries;
    }

    if (closedir(dir) < 0)
        return -1;

    *count = entries;
    return 0;
}

int
main(void)
{
    char template[] = "/tmp/store-session-key-test.XXXXXX";
    char *directory = mkdtemp(template);
    if (directory == NULL)
        return 1;

    char destination[PATH_MAX];
    char linkpath[PATH_MAX];
    char target[PATH_MAX];
    char missing_path[PATH_MAX];

    if (snprintf(destination, sizeof(destination), "%s/key", directory) >=
            (int)sizeof(destination) ||
        snprintf(linkpath, sizeof(linkpath), "%s/link", directory) >=
            (int)sizeof(linkpath) ||
        snprintf(target, sizeof(target), "%s/target", directory) >=
            (int)sizeof(target) ||
        snprintf(missing_path, sizeof(missing_path), "%s/missing/key",
                 directory) >= (int)sizeof(missing_path))
        return 1;

    const uint8_t key[] = { 0x00, 0x12, 0x34, 0x56, 0x78, 0xff };
    uint8_t serialized[SESSION_KEY_HEADER_SIZE + sizeof(key)];
    size_t serialized_len = 0;

    if (store_session_key(destination, key, sizeof(key)) != 0)
        return 1;

    if (test_read_file(destination, serialized, sizeof(serialized),
                       &serialized_len) != 0 ||
        serialized_len != sizeof(serialized))
        return 1;

    const uint8_t expected_header[SESSION_KEY_HEADER_SIZE] = {
        'S', 'S', 'K', 'Y', 0, SESSION_KEY_VERSION, 0, 0, 0, sizeof(key)
    };
    if (memcmp(serialized, expected_header, sizeof(expected_header)) != 0 ||
        memcmp(serialized + SESSION_KEY_HEADER_SIZE, key, sizeof(key)) != 0)
        return 1;

    struct stat st;
    if (stat(destination, &st) != 0 ||
        !S_ISREG(st.st_mode) ||
        st.st_uid != getuid() ||
        (st.st_mode & 07777) != 0600)
        return 1;

    errno = 0;
    if (store_session_key(destination, NULL, sizeof(key)) != -1 ||
        errno != EINVAL)
        return 1;
    errno = 0;
    if (store_session_key(destination, key, 0) != -1 || errno != EINVAL)
        return 1;
    errno = 0;
    if (store_session_key(destination, key, (size_t)UINT32_MAX + 1U) != -1 ||
        errno != EINVAL)
        return 1;
    errno = 0;
    if (store_session_key(NULL, key, sizeof(key)) != -1 || errno != EINVAL)
        return 1;

    const uint8_t original_target[] = { 'u', 'n', 'c', 'h', 'a', 'n', 'g', 'e', 'd' };
    int target_fd = open(target, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (target_fd < 0)
        return 1;
    if (session_key_write_all(target_fd, original_target,
                              sizeof(original_target)) < 0 ||
        close(target_fd) < 0)
        return 1;

    if (symlink(target, linkpath) != 0)
        return 1;

    errno = 0;
    if (store_session_key(linkpath, key, sizeof(key)) != -1 ||
        errno != ELOOP)
        return 1;

    uint8_t target_readback[sizeof(original_target)];
    size_t target_readback_len = 0;
    if (test_read_file(target, target_readback, sizeof(target_readback),
                       &target_readback_len) != 0 ||
        target_readback_len != sizeof(original_target) ||
        memcmp(target_readback, original_target, sizeof(original_target)) != 0)
        return 1;

    errno = 0;
    if (store_session_key(missing_path, key, sizeof(key)) != -1)
        return 1;

    size_t entries_before = 0;
    size_t entries_after = 0;
    if (test_directory_entry_count(directory, &entries_before) != 0)
        return 1;

    char directory_destination[PATH_MAX];
    if (snprintf(directory_destination, sizeof(directory_destination),
                 "%s/subdir", directory) >= (int)sizeof(directory_destination) ||
        mkdir(directory_destination, 0700) != 0)
        return 1;

    errno = 0;
    if (store_session_key(directory_destination, key, sizeof(key)) != -1)
        return 1;

    if (test_directory_entry_count(directory, &entries_after) != 0 ||
        entries_after != entries_before + 1)
        return 1;

    if (unlink(linkpath) != 0 ||
        unlink(target) != 0 ||
        unlink(destination) != 0 ||
        rmdir(directory_destination) != 0 ||
        rmdir(directory) != 0)
        return 1;

    return 0;
}

#endif