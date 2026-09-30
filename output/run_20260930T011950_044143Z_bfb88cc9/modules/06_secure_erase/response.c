#define _GNU_SOURCE
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>
#include <errno.h>

int secure_erase(const char *path)
{
    static const unsigned char zeros[65536] = {0};
    struct stat st;
    off_t offset = 0;
    int fd;

    if (path == NULL)
        return -1;

    do {
        fd = open(path, O_WRONLY | O_CLOEXEC);
    } while (fd < 0 && errno == EINTR);

    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0 || st.st_size < 0) {
        (void)close(fd);
        return -1;
    }

    while (offset < st.st_size) {
        off_t remaining = st.st_size - offset;
        size_t chunk = remaining < (off_t)sizeof(zeros)
                           ? (size_t)remaining
                           : sizeof(zeros);
        ssize_t written = pwrite(fd, zeros, chunk, offset);

        if (written < 0) {
            if (errno == EINTR)
                continue;
            (void)close(fd);
            return -1;
        }
        if (written == 0) {
            (void)close(fd);
            return -1;
        }
        offset += written;
    }

    if (close(fd) < 0)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}