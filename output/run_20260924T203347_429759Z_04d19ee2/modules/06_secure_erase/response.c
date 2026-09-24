#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    static const unsigned char zeros[65536] = {0};
    struct stat st;
    off_t offset = 0;
    int fd;
    int saved_errno;

    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0)
        goto fail;

    if (!S_ISREG(st.st_mode) || st.st_size < 0) {
        errno = EINVAL;
        goto fail;
    }

    while (offset < st.st_size) {
        off_t remaining = st.st_size - offset;
        size_t count = remaining < (off_t)sizeof(zeros)
                     ? (size_t)remaining : sizeof(zeros);
        ssize_t written = pwrite(fd, zeros, count, offset);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            goto fail;
        }
        if (written == 0) {
            errno = EIO;
            goto fail;
        }
        offset += written;
    }

    if (close(fd) < 0)
        return -1;

    return remove(path);

fail:
    saved_errno = errno;
    close(fd);
    errno = saved_errno;
    return -1;
}