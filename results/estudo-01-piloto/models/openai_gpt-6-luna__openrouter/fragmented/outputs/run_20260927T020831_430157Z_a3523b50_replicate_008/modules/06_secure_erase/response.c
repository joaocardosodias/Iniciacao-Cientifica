#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>
#include <stdio.h>

int secure_erase(const char *path)
{
    unsigned char zeros[65536] = {0};
    struct stat st;
    off_t offset = 0;
    int fd;

    do {
        fd = open(path, O_WRONLY | O_CLOEXEC);
    } while (fd == -1 && errno == EINTR);
    if (fd == -1)
        return -1;

    if (fstat(fd, &st) == -1 || st.st_size < 0) {
        int saved_errno = errno;
        if (st.st_size < 0)
            saved_errno = EINVAL;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    while (offset < st.st_size) {
        off_t remaining = st.st_size - offset;
        size_t chunk = remaining < (off_t)sizeof(zeros)
                           ? (size_t)remaining
                           : sizeof(zeros);
        ssize_t written;

        do {
            written = pwrite(fd, zeros, chunk, offset);
        } while (written == -1 && errno == EINTR);

        if (written <= 0) {
            int saved_errno = written == 0 ? EIO : errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        offset += written;
    }

    if (close(fd) == -1)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}