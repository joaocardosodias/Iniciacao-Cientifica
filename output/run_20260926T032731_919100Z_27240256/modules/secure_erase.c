#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <errno.h>

int secure_erase(const char *path)
{
    int fd = -1;
    struct stat st;
    ssize_t to_write;
    ssize_t written;
    const size_t bufsize = 4096;
    static const char zero_buf[4096] = {0};
    int ret = -1;

    if (!path)
        return -1;

    fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0)
        goto cleanup_fd;

    to_write = st.st_size;
    while (to_write > 0) {
        size_t chunk = (size_t)(to_write < (ssize_t)bufsize ? to_write : bufsize);
        written = write(fd, zero_buf, chunk);
        if (written != (ssize_t)chunk) {
            /* write error */
            goto cleanup_fd;
        }
        to_write -= written;
    }

    /* Ensure data is flushed to disk */
    if (fsync(fd) < 0)
        goto cleanup_fd;

    if (close(fd) < 0)
        return -1;
    fd = -1; /* closed successfully */

    if (remove(path) != 0)
        return -1;

    return 0;

cleanup_fd:
    if (fd >= 0) {
        int saved_errno = errno;
        close(fd);
        errno = saved_errno;
    }
    return -1;
}