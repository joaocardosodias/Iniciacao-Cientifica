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
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd == -1)
        return -1;

    int result = 0;
    if (fstat(fd, &st) == -1 || st.st_size < 0) {
        result = -1;
    } else {
        off_t offset = 0;
        off_t remaining = st.st_size;

        while (remaining > 0) {
            size_t amount = remaining > (off_t)sizeof(zeros)
                                ? sizeof(zeros)
                                : (size_t)remaining;
            ssize_t written = pwrite(fd, zeros, amount, offset);

            if (written == -1 && errno == EINTR)
                continue;
            if (written <= 0) {
                result = -1;
                break;
            }

            offset += written;
            remaining -= written;
        }
    }

    if (close(fd) == -1)
        result = -1;
    if (result == -1)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}