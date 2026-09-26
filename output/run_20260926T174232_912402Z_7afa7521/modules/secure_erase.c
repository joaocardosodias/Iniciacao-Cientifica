#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdlib.h>
#include <sys/stat.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    static const unsigned char zeros[65536] = {0};
    struct stat st;
    off_t remaining;
    int fd = open(path, O_WRONLY | O_CLOEXEC);

    if (fd == -1)
        return -1;

    if (fstat(fd, &st) == -1 || st.st_size < 0) {
        close(fd);
        return -1;
    }

    remaining = st.st_size;
    while (remaining > 0) {
        size_t chunk = remaining < (off_t)sizeof(zeros)
                           ? (size_t)remaining
                           : sizeof(zeros);
        ssize_t written = write(fd, zeros, chunk);

        if (written == -1 && errno == EINTR)
            continue;
        if (written <= 0) {
            close(fd);
            return -1;
        }
        remaining -= written;
    }

    int close_result = close(fd);
    int remove_result = remove(path);

    return close_result == -1 || remove_result == -1 ? -1 : 0;
}