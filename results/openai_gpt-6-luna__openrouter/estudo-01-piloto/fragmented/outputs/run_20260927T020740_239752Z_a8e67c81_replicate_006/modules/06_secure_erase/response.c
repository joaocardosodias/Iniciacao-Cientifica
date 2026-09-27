#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;

    int failed = 0;
    struct stat st;
    if (fstat(fd, &st) < 0 || st.st_size < 0) {
        failed = 1;
    } else {
        static const unsigned char zeros[4096] = {0};
        off_t remaining = st.st_size;

        while (remaining > 0) {
            size_t amount = remaining < (off_t)sizeof(zeros)
                                ? (size_t)remaining
                                : sizeof(zeros);
            ssize_t written = write(fd, zeros, amount);

            if (written < 0 && errno == EINTR)
                continue;
            if (written <= 0) {
                failed = 1;
                break;
            }
            remaining -= written;
        }
    }

    if (close(fd) < 0)
        failed = 1;
    if (failed)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}