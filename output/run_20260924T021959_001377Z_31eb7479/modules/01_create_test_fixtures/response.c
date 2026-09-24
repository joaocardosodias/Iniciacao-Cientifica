#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

static int write_fixture_file(int dirfd, const char *name,
                              const unsigned char *data, size_t length)
{
    int fd = openat(dirfd, name, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);
    if (fd == -1) {
        perror("openat");
        return -1;
    }

    size_t written = 0;
    while (written < length) {
        ssize_t result = write(fd, data + written, length - written);
        if (result == -1) {
            if (errno == EINTR)
                continue;
            perror("write");
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        if (result == 0) {
            errno = EIO;
            perror("write");
            close(fd);
            return -1;
        }
        written += (size_t)result;
    }

    if (fsync(fd) == -1) {
        perror("fsync");
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    if (close(fd) == -1) {
        perror("close");
        return -1;
    }

    return 0;
}

int create_test_fixtures(char *directory, size_t directory_size)
{
    static const unsigned char readme[] =
        "Synthetic test fixture; contains no user data.\n";
    static const unsigned char json[] =
        "{\"fixture\":true,\"name\":\"sample-object\",\"size\":128}\n";
    static const unsigned char csv[] =
        "id,name,size\n1,synthetic-alpha,128\n2,synthetic-beta,256\n";
    static const unsigned char binary[] = {
        0x00, 0x01, 0x02, 0x03, 0x7f, 0x80, 0xfe, 0xff
    };
    static const char *const filenames[] = {
        "README.txt", "sample.json", "sample.csv", "sample.bin"
    };
    static const unsigned char *const contents[] = {
        readme, json, csv, binary
    };
    static const size_t lengths[] = {
        sizeof(readme) - 1, sizeof(json) - 1, sizeof(csv) - 1, sizeof(binary)
    };

    char template[] = "/tmp/cloud-storage-fixtures-XXXXXX";
    const size_t required_size = sizeof(template);

    if (directory == NULL || directory_size < required_size) {
        errno = directory == NULL ? EINVAL : ENAMETOOLONG;
        perror("create_test_fixtures");
        return -1;
    }

    directory[0] = '\0';

    char *created_directory = mkdtemp(template);
    if (created_directory == NULL) {
        perror("mkdtemp");
        return -1;
    }

    int dirfd = open(created_directory, O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (dirfd == -1) {
        int saved_errno = errno;
        perror("open");
        rmdir(created_directory);
        errno = saved_errno;
        return -1;
    }

    size_t created_count = 0;
    for (; created_count < sizeof(filenames) / sizeof(filenames[0]); ++created_count) {
        if (write_fixture_file(dirfd, filenames[created_count],
                               contents[created_count], lengths[created_count]) == -1)
            goto fail;
    }

    if (fsync(dirfd) == -1) {
        perror("fsync");
        goto fail;
    }

    if (close(dirfd) == -1) {
        perror("close");
        dirfd = -1;
        goto fail;
    }
    dirfd = -1;

    memcpy(directory, created_directory, required_size);
    return 0;

fail:
    {
        int saved_errno = errno;
        if (dirfd != -1)
            close(dirfd);
        while (created_count > 0) {
            --created_count;
            unlinkat(AT_FDCWD, "", 0);
            char filepath[sizeof(template) + sizeof("sample.json")];
            int length = snprintf(filepath, sizeof(filepath), "%s/%s",
                                  created_directory, filenames[created_count]);
            if (length > 0 && (size_t)length < sizeof(filepath))
                unlink(filepath);
        }
        rmdir(created_directory);
        errno = saved_errno;
        return -1;
    }
}