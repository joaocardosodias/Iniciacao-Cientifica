#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stddef.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    static const unsigned char zeros[65536] = {0};
    struct stat st;
    off_t remaining;
    int fd;

    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    if (!S_ISREG(st.st_mode) || st.st_size < 0) {
        close(fd);
        errno = EINVAL;
        return -1;
    }

    remaining = st.st_size;
    while (remaining > 0) {
        size_t count = remaining > (off_t)sizeof(zeros)
                     ? sizeof(zeros) : (size_t)remaining;
        ssize_t written = write(fd, zeros, count);

        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0) {
            int saved_errno = written == 0 ? EIO : errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        remaining -= written;
    }

    if (close(fd) < 0)
        return -1;

    return remove(path);
}