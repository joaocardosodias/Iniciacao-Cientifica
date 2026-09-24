#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    static const unsigned char zeros[16384] = {0};
    struct stat st;
    off_t remaining;
    int fd;

    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = open(path, O_WRONLY | O_CLOEXEC | O_NOFOLLOW);
    if (fd == -1)
        return -1;

    if (fstat(fd, &st) == -1) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        close(fd);
        errno = EINVAL;
        return -1;
    }

    remaining = st.st_size;
    while (remaining > 0) {
        size_t count = remaining > (off_t)sizeof(zeros)
                           ? sizeof(zeros)
                           : (size_t)remaining;
        ssize_t written = write(fd, zeros, count);

        if (written == -1 && errno == EINTR)
            continue;
        if (written <= 0) {
            int saved_errno = written == 0 ? EIO : errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        remaining -= written;
    }

    if (fsync(fd) == -1) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    if (close(fd) == -1)
        return -1;

    return remove(path);
}