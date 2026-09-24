#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

typedef struct {
    const char *path;
    int altered;
} altered_file;

enum notice_action_result {
    NOTICE_ACTION_FAILURE = -1,
    NOTICE_ACTION_SUCCESS = 0,
    NOTICE_ACTION_PARTIAL = 1
};

static const char notice_filename[] = "#_STATUS_NOTICE_#.txt";
static const char notice_contents[] =
    "Unauthorized changes to files in this directory have been detected.\n"
    "Do not modify, move, or otherwise alter the affected files. Contact "
    "your organization's incident response team using the secure support "
    "channel previously provided by your organization.\n";

static int
write_all(int fd, const char *buffer, size_t length)
{
    size_t written = 0;

    while (written < length) {
        ssize_t result = write(fd, buffer + written, length - written);
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
create_notice_in_directory(const char *directory)
{
    int dirfd = -1;
    int fd = -1;
    char temporary_name[128];
    unsigned int attempt;
    int result = -1;
    int saved_errno;

    dirfd = open(directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (dirfd < 0) {
        syslog(LOG_ERR, "Cannot open affected directory %s: %s",
               directory, strerror(errno));
        return -1;
    }

    for (attempt = 0; attempt < 128; ++attempt) {
        int length = snprintf(temporary_name, sizeof(temporary_name),
                              ".notice.tmp.%ld.%u", (long)getpid(), attempt);
        if (length < 0 || (size_t)length >= sizeof(temporary_name)) {
            errno = ENAMETOOLONG;
            break;
        }

        fd = openat(dirfd, temporary_name,
                    O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                    0644);
        if (fd >= 0)
            break;
        if (errno != EEXIST)
            break;
    }

    if (fd < 0) {
        syslog(LOG_ERR, "Cannot create temporary notice in %s: %s",
               directory, strerror(errno));
        close(dirfd);
        return -1;
    }

    if (write_all(fd, notice_contents, sizeof(notice_contents) - 1) < 0 ||
        fsync(fd) < 0) {
        saved_errno = errno;
        close(fd);
        unlinkat(dirfd, temporary_name, 0);
        close(dirfd);
        errno = saved_errno;
        syslog(LOG_ERR, "Cannot write notice in %s: %s",
               directory, strerror(errno));
        return -1;
    }

    if (close(fd) < 0) {
        saved_errno = errno;
        unlinkat(dirfd, temporary_name, 0);
        close(dirfd);
        errno = saved_errno;
        syslog(LOG_ERR, "Cannot close notice in %s: %s",
               directory, strerror(errno));
        return -1;
    }
    fd = -1;

    if (linkat(dirfd, temporary_name, dirfd, notice_filename, 0) < 0) {
        saved_errno = errno;
        if (saved_errno == EEXIST) {
            if (unlinkat(dirfd, temporary_name, 0) < 0) {
                syslog(LOG_ERR, "Cannot remove temporary notice in %s: %s",
                       directory, strerror(errno));
                close(dirfd);
                return -1;
            }
            syslog(LOG_INFO, "Notice already exists in %s", directory);
            close(dirfd);
            return 0;
        }

        unlinkat(dirfd, temporary_name, 0);
        close(dirfd);
        errno = saved_errno;
        syslog(LOG_ERR, "Cannot install notice in %s: %s",
               directory, strerror(errno));
        return -1;
    }

    if (unlinkat(dirfd, temporary_name, 0) < 0) {
        syslog(LOG_ERR, "Notice created, but temporary file cleanup failed in %s: %s",
               directory, strerror(errno));
        close(dirfd);
        return -1;
    }

    if (fsync(dirfd) < 0) {
        syslog(LOG_ERR, "Notice created, but directory sync failed in %s: %s",
               directory, strerror(errno));
        close(dirfd);
        return -1;
    }

    if (close(dirfd) < 0) {
        syslog(LOG_ERR, "Notice created, but directory close failed for %s: %s",
               directory, strerror(errno));
        return -1;
    }

    result = 0;
    return result;
}

int
notice_and_action_execution(const altered_file *files, size_t file_count)
{
    char **seen_directories;
    size_t seen_count = 0;
    size_t successes = 0;
    size_t failures = 0;
    size_t i;

    if (file_count == 0)
        return NOTICE_ACTION_SUCCESS;

    if (files == NULL) {
        syslog(LOG_ERR, "Invalid altered-file list");
        return NOTICE_ACTION_FAILURE;
    }

    if (file_count > (size_t)-1 / sizeof(*seen_directories)) {
        syslog(LOG_ERR, "Altered-file list is too large");
        return NOTICE_ACTION_FAILURE;
    }

    seen_directories = calloc(file_count, sizeof(*seen_directories));
    if (seen_directories == NULL) {
        syslog(LOG_ERR, "Cannot allocate affected-directory list: %s",
               strerror(errno));
        return NOTICE_ACTION_FAILURE;
    }

    for (i = 0; i < file_count; ++i) {
        const char *path;
        const char *last_slash;
        size_t path_length;
        size_t directory_length;
        char directory_input[PATH_MAX];
        char canonical_directory[PATH_MAX];
        char *directory_copy;
        size_t j;
        int duplicate = 0;

        if (!files[i].altered)
            continue;

        path = files[i].path;
        if (path == NULL || path[0] == '\0') {
            syslog(LOG_ERR, "Invalid path for an altered file");
            ++failures;
            continue;
        }

        path_length = strnlen(path, PATH_MAX + 1);
        if (path_length == 0 || path_length > PATH_MAX) {
            syslog(LOG_ERR, "Path for an altered file is too long or invalid");
            ++failures;
            continue;
        }

        last_slash = strrchr(path, '/');
        if (last_slash == NULL) {
            directory_length = 1;
            directory_input[0] = '.';
            directory_input[1] = '\0';
        } else {
            size_t base_length = path_length - (size_t)(last_slash - path) - 1;
            if (base_length == 0 ||
                (base_length == 1 && last_slash[1] == '.') ||
                (base_length == 2 && last_slash[1] == '.' &&
                 last_slash[2] == '.')) {
                syslog(LOG_ERR, "Invalid file path for an altered file: %s",
                       path);
                ++failures;
                continue;
            }

            directory_length = (size_t)(last_slash - path);
            if (directory_length == 0) {
                directory_input[0] = '/';
                directory_input[1] = '\0';
            } else {
                if (directory_length >= sizeof(directory_input)) {
                    syslog(LOG_ERR, "Directory path is too long: %s", path);
                    ++failures;
                    continue;
                }
                memcpy(directory_input, path, directory_length);
                directory_input[directory_length] = '\0';
            }
        }

        if (realpath(directory_input, canonical_directory) == NULL) {
            syslog(LOG_ERR, "Cannot resolve directory for altered file %s: %s",
                   path, strerror(errno));
            ++failures;
            continue;
        }

        for (j = 0; j < seen_count; ++j) {
            if (strcmp(seen_directories[j], canonical_directory) == 0) {
                duplicate = 1;
                break;
            }
        }
        if (duplicate)
            continue;

        directory_copy = strdup(canonical_directory);
        if (directory_copy == NULL) {
            syslog(LOG_ERR, "Cannot record affected directory %s: %s",
                   canonical_directory, strerror(errno));
            ++failures;
            continue;
        }
        seen_directories[seen_count++] = directory_copy;

        if (create_notice_in_directory(canonical_directory) == 0)
            ++successes;
        else
            ++failures;
    }

    for (i = 0; i < seen_count; ++i)
        free(seen_directories[i]);
    free(seen_directories);

    if (failures == 0)
        return NOTICE_ACTION_SUCCESS;
    if (successes == 0)
        return NOTICE_ACTION_FAILURE;
    return NOTICE_ACTION_PARTIAL;
}