#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

int secure_erase(const char *path)
{
    static const unsigned char zeros[65536] = {0};
    struct stat st;
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0 || st.st_size < 0) {
        int saved_errno = errno ? errno : EIO;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    off_t offset = 0;
    while (offset < st.st_size) {
        off_t remaining = st.st_size - offset;
        size_t length = remaining < (off_t)sizeof(zeros)
                            ? (size_t)remaining
                            : sizeof(zeros);
        ssize_t written = pwrite(fd, zeros, length, offset);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            int saved_errno = errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        if (written == 0) {
            close(fd);
            errno = EIO;
            return -1;
        }
        offset += written;
    }

    if (close(fd) < 0)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}