#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    static const unsigned char zeros[65536] = { 0 };
    struct stat st;
    off_t offset = 0;
    int fd;

    if (path == NULL) {
        errno = EINVAL;
        return -1;
    }

    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0 || st.st_size < 0) {
        int saved_errno = st.st_size < 0 ? EINVAL : errno;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    while (offset < st.st_size) {
        off_t remaining = st.st_size - offset;
        size_t count = remaining < (off_t)sizeof(zeros)
            ? (size_t)remaining
            : sizeof(zeros);
        ssize_t written = pwrite(fd, zeros, count, offset);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            {
                int saved_errno = errno;
                close(fd);
                errno = saved_errno;
            }
            return -1;
        }
        if (written == 0) {
            int saved_errno = EIO;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        offset += written;
    }

    if (close(fd) < 0)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}