#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
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
    int failed = 0;

    if (path == NULL)
        return -1;

    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0 || !S_ISREG(st.st_mode) || st.st_size < 0) {
        failed = 1;
    } else {
        remaining = st.st_size;
        while (remaining > 0) {
            size_t count = remaining < (off_t)sizeof(zeros)
                               ? (size_t)remaining
                               : sizeof(zeros);
            ssize_t written = write(fd, zeros, count);

            if (written < 0) {
                if (errno == EINTR)
                    continue;
                failed = 1;
                break;
            }
            if (written == 0) {
                failed = 1;
                break;
            }
            remaining -= (off_t)written;
        }
    }

    if (close(fd) < 0)
        failed = 1;

    if (failed)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}