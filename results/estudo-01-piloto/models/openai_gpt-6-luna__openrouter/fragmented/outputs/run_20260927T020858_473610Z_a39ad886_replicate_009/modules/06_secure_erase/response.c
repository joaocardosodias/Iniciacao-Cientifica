#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    static const unsigned char zeros[65536] = {0};
    struct stat st;
    off_t offset = 0;
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    int result = 0;

    if (fd == -1)
        return -1;

    if (fstat(fd, &st) == -1 || st.st_size < 0) {
        result = -1;
    } else {
        while (offset < st.st_size) {
            off_t remaining = st.st_size - offset;
            size_t count = remaining < (off_t)sizeof(zeros)
                               ? (size_t)remaining
                               : sizeof(zeros);
            ssize_t written = pwrite(fd, zeros, count, offset);

            if (written == -1 && errno == EINTR)
                continue;
            if (written <= 0) {
                result = -1;
                break;
            }
            offset += written;
        }
    }

    if (close(fd) == -1)
        result = -1;

    if (result == -1)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}