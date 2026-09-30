#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <stdio.h>
#include <sys/stat.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    int fd;
    struct stat st;
    static const unsigned char zeros[4096] = {0};
    off_t remaining;
    int failed = 0;

    if (path == NULL)
        return -1;

    fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0 || st.st_size < 0) {
        failed = 1;
    } else {
        remaining = st.st_size;
        while (remaining > 0) {
            size_t count = remaining > (off_t)sizeof(zeros)
                               ? sizeof(zeros)
                               : (size_t)remaining;
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
            remaining -= written;
        }
    }

    if (close(fd) < 0)
        failed = 1;

    if (failed)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}