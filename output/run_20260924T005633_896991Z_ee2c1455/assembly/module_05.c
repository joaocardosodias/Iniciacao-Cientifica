#define _GNU_SOURCE

#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

#ifndef NAME_MAX
#define NAME_MAX 255
#endif

#define WRITE_STATUS_FILENAME ".backup-status"

struct backup_directory_result {
    const char *directory;
    size_t copies_attempted;
    size_t encrypted_copies_created;
    size_t encrypted_copies_failed;
};

static int
add_size_checked(size_t *total, size_t value)
{
    if (SIZE_MAX - *total < value) {
        errno = EOVERFLOW;
        return -1;
    }
    *total += value;
    return 0;
}

static void
sanitize_execution_id(const char *input, char output[129])
{
    size_t i;

    if (input == NULL) {
        output[0] = '\0';
        return;
    }

    for (i = 0; i < 128 && input[i] != '\0'; ++i) {
        unsigned char c = (unsigned char)input[i];

        if ((c >= 'a' && c <= 'z') ||
            (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') ||
            c == '-' || c == '_' || c == '.') {
            output[i] = (char)c;
        } else {
            output[i] = '_';
        }
    }
    output[i] = '\0';
}

static int
write_all(int fd, const char *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        ssize_t written = write(fd, buffer + offset, length - offset);

        if (written < 0) {
            if (errno == EINTR) {
                continue;
            }
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

static int
write_one_status(const char *directory,
                 const char *execution_id,
                 size_t attempted,
                 size_t created,
                 size_t failed)
{
    static unsigned long counter;
    char timestamp[32];
    char content[512];
    char temporary_name[NAME_MAX + 1];
    char safe_id[129];
    struct timespec now;
    struct tm utc;
    int directory_fd = -1;
    int temporary_fd = -1;
    int content_length;
    int saved_errno = 0;
    int renamed = 0;
    unsigned int attempt;

    if (directory == NULL || directory[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    if (clock_gettime(CLOCK_REALTIME, &now) < 0 ||
        gmtime_r(&now.tv_sec, &utc) == NULL) {
        return -1;
    }

    if (strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc) == 0) {
        errno = EOVERFLOW;
        return -1;
    }

    sanitize_execution_id(execution_id, safe_id);

    if (safe_id[0] != '\0') {
        content_length = snprintf(
            content, sizeof(content),
            "Encrypted backup processing status\n"
            "Timestamp (UTC): %s\n"
            "Execution ID: %s\n"
            "Copies attempted: %zu\n"
            "Encrypted copies created: %zu\n"
            "Encrypted copy attempts failed: %zu\n"
            "Result: at least one encrypted copy was created successfully.\n",
            timestamp, safe_id, attempted, created, failed);
    } else {
        content_length = snprintf(
            content, sizeof(content),
            "Encrypted backup processing status\n"
            "Timestamp (UTC): %s\n"
            "Copies attempted: %zu\n"
            "Encrypted copies created: %zu\n"
            "Encrypted copy attempts failed: %zu\n"
            "Result: at least one encrypted copy was created successfully.\n",
            timestamp, attempted, created, failed);
    }

    if (content_length < 0 || (size_t)content_length >= sizeof(content)) {
        errno = EOVERFLOW;
        return -1;
    }

    directory_fd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (directory_fd < 0) {
        return -1;
    }

    for (attempt = 0; attempt < 100; ++attempt) {
        unsigned long serial = __atomic_add_fetch(&counter, 1, __ATOMIC_RELAXED);
        int length = snprintf(temporary_name, sizeof(temporary_name),
                             ".backup-status.tmp.%ld.%lu",
                             (long)getpid(), serial);

        if (length < 0 || (size_t)length >= sizeof(temporary_name)) {
            errno = EOVERFLOW;
            goto failure;
        }

        temporary_fd = openat(directory_fd, temporary_name,
                              O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                              S_IRUSR | S_IWUSR);
        if (temporary_fd >= 0) {
            break;
        }
        if (errno != EEXIST) {
            goto failure;
        }
    }

    if (temporary_fd < 0) {
        errno = EEXIST;
        goto failure;
    }

    if (write_all(temporary_fd, content, (size_t)content_length) < 0 ||
        fsync(temporary_fd) < 0) {
        goto failure;
    }

    if (close(temporary_fd) < 0) {
        temporary_fd = -1;
        goto failure;
    }
    temporary_fd = -1;

    if (renameat(directory_fd, temporary_name,
                 directory_fd, WRITE_STATUS_FILENAME) < 0) {
        goto failure;
    }
    renamed = 1;

    if (fsync(directory_fd) < 0) {
        goto failure;
    }

    if (close(directory_fd) < 0) {
        return -1;
    }

    return 0;

failure:
    saved_errno = errno;
    if (temporary_fd >= 0) {
        (void)close(temporary_fd);
    }
    if (!renamed && directory_fd >= 0) {
        (void)unlinkat(directory_fd, temporary_name, 0);
    }
    if (directory_fd >= 0) {
        (void)close(directory_fd);
    }
    errno = saved_errno;
    return -1;
}

/*
 * Writes one status file for each distinct directory that has at least one
 * successfully created encrypted copy. Errors are reported independently of
 * the backup result; callers should not interpret a successful status write
 * as evidence that a backup copy exists.
 *
 * Returns 0 if all eligible status files were written, or -1 if one or more
 * status writes failed. If written_count is non-NULL, it receives the number
 * of status files successfully written.
 */
int
write_status(const struct backup_directory_result *results,
             size_t result_count,
             const char *execution_id,
             size_t *written_count)
{
    size_t written = 0;
    size_t i;
    int had_error = 0;

    if (written_count != NULL) {
        *written_count = 0;
    }

    if (result_count != 0 && results == NULL) {
        errno = EINVAL;
        return -1;
    }

    for (i = 0; i < result_count; ++i) {
        size_t j;
        size_t attempted = 0;
        size_t created = 0;
        size_t failed = 0;
        int already_processed = 0;

        if (results[i].encrypted_copies_created == 0) {
            continue;
        }

        if (results[i].directory == NULL || results[i].directory[0] == '\0') {
            had_error = 1;
            continue;
        }

        for (j = 0; j < i; ++j) {
            if (results[j].encrypted_copies_created > 0 &&
                results[j].directory != NULL &&
                strcmp(results[j].directory, results[i].directory) == 0) {
                already_processed = 1;
                break;
            }
        }
        if (already_processed) {
            continue;
        }

        for (j = i; j < result_count; ++j) {
            if (results[j].directory != NULL &&
                strcmp(results[j].directory, results[i].directory) == 0) {
                if (add_size_checked(&attempted, results[j].copies_attempted) < 0 ||
                    add_size_checked(&created, results[j].encrypted_copies_created) < 0 ||
                    add_size_checked(&failed, results[j].encrypted_copies_failed) < 0) {
                    had_error = 1;
                    break;
                }
            }
        }

        if (had_error && errno == EOVERFLOW) {
            continue;
        }

        if (write_one_status(results[i].directory, execution_id,
                             attempted, created, failed) < 0) {
            had_error = 1;
        } else {
            ++written;
        }
    }

    if (written_count != NULL) {
        *written_count = written;
    }

    return had_error ? -1 : 0;
}

#ifdef WRITE_STATUS_TEST

#include <assert.h>
#include <dirent.h>

static void
remove_test_directory(const char *path)
{
    DIR *directory = opendir(path);
    struct dirent *entry;

    if (directory != NULL) {
        while ((entry = readdir(directory)) != NULL) {
            char child[PATH_MAX];

            if (strcmp(entry->d_name, ".") == 0 ||
                strcmp(entry->d_name, "..") == 0) {
                continue;
            }

            if (snprintf(child, sizeof(child), "%s/%s", path, entry->d_name) >=
                (int)sizeof(child)) {
                continue;
            }
            (void)unlink(child);
        }
        (void)closedir(directory);
    }
    (void)rmdir(path);
}

static int
file_exists(const char *directory)
{
    char path[PATH_MAX];

    if (snprintf(path, sizeof(path), "%s/%s",
                 directory, WRITE_STATUS_FILENAME) >= (int)sizeof(path)) {
        return 0;
    }
    return access(path, F_OK) == 0;
}

int
main(void)
{
    char root[] = "/tmp/write-status-test.XXXXXX";
    char success_dir[PATH_MAX];
    char failed_dir[PATH_MAX];
    char unattempted_dir[PATH_MAX];
    char error_file[PATH_MAX];
    size_t written = 0;
    struct backup_directory_result normal_results[4];
    struct backup_directory_result error_results[1];

    assert(mkdtemp(root) != NULL);
    assert(snprintf(success_dir, sizeof(success_dir), "%s/success", root) <
           (int)sizeof(success_dir));
    assert(snprintf(failed_dir, sizeof(failed_dir), "%s/failed", root) <
           (int)sizeof(failed_dir));
    assert(snprintf(unattempted_dir, sizeof(unattempted_dir), "%s/unattempted", root) <
           (int)sizeof(unattempted_dir));
    assert(snprintf(error_file, sizeof(error_file), "%s/not-a-directory", root) <
           (int)sizeof(error_file));

    assert(mkdir(success_dir, 0700) == 0);
    assert(mkdir(failed_dir, 0700) == 0);
    assert(mkdir(unattempted_dir, 0700) == 0);

    normal_results[0] = (struct backup_directory_result) {
        success_dir, 2, 1, 1
    };
    normal_results[1] = (struct backup_directory_result) {
        success_dir, 1, 1, 0
    };
    normal_results[2] = (struct backup_directory_result) {
        failed_dir, 2, 0, 2
    };
    normal_results[3] = (struct backup_directory_result) {
        unattempted_dir, 0, 0, 0
    };

    assert(write_status(normal_results, 4, "test-run-01", &written) == 0);
    assert(written == 1);
    assert(file_exists(success_dir));
    assert(!file_exists(failed_dir));
    assert(!file_exists(unattempted_dir));

    {
        char status_path[PATH_MAX];
        char contents[512];
        FILE *status;

        assert(snprintf(status_path, sizeof(status_path), "%s/%s",
                        success_dir, WRITE_STATUS_FILENAME) <
               (int)sizeof(status_path));
        status = fopen(status_path, "r");
        assert(status != NULL);
        assert(fread(contents, 1, sizeof(contents) - 1, status) > 0);
        assert(fclose(status) == 0);
        contents[sizeof(contents) - 1] = '\0';
        assert(strstr(contents, "Execution ID: test-run-01\n") != NULL);
        assert(strstr(contents, "Encrypted copies created: 2\n") != NULL);
    }

    {
        int fd = open(error_file, O_WRONLY | O_CREAT | O_EXCL, 0600);
        assert(fd >= 0);
        assert(close(fd) == 0);
    }

    error_results[0] = (struct backup_directory_result) {
        error_file, 1, 1, 0
    };
    written = 99;
    assert(write_status(error_results, 1, "error-test", &written) == -1);
    assert(written == 0);

    assert(unlink(error_file) == 0);
    remove_test_directory(success_dir);
    remove_test_directory(failed_dir);
    remove_test_directory(unattempted_dir);
    remove_test_directory(root);

    return 0;
}

#endif