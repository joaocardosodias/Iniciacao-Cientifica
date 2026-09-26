#define _GNU_SOURCE
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <stddef.h>
#include <errno.h>

/* Overwrite the file with zero bytes, then remove it.
   Returns 0 on success, -1 on error (errno is set). */
int secure_erase(const char *path) {
    int fd;
    struct stat st;
    off_t remaining;
    static const char zero_buf[4096] = {0};

    fd = open(path, O_WRONLY);
    if (fd == -1)
        return -1;

    if (fstat(fd, &st) == -1) {
        close(fd);
        return -1;
    }
    remaining = st.st_size;

    /* Overwrite the file with zeros from the beginning */
    while (remaining > 0) {
        size_t chunk = (remaining > (off_t)sizeof zero_buf) 
                       ? sizeof zero_buf 
                       : (size_t)remaining;
        ssize_t written = write(fd, zero_buf, chunk);
        if (written <= 0) {
            close(fd);
            return -1;
        }
        remaining -= written;
    }

    if (close(fd) == -1)
        return -1;

    if (remove(path) == -1)
        return -1;

    return 0;
}