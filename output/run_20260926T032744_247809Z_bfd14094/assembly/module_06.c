#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <syslog.h>
#include <wchar.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <errno.h>

static int overwrite_with_zeros(int fd, off_t size)
{
    const size_t bufsize = 4096;
    char zero_buf[bufsize];
    memset(zero_buf, 0, bufsize);

    off_t written = 0;
    while (written < size) {
        size_t to_write = (size - written) < (off_t)bufsize ? (size - written) : bufsize;
        ssize_t w = write(fd, zero_buf, to_write);
        if (w <= 0) {
            return -1;
        }
        written += w;
    }
    if (fsync(fd) < 0) {
        return -1;
    }
    return 0;
}

int secure_erase(const char *path)
{
    if (!path) {
        errno = EINVAL;
        return -1;
    }

    int fd = open(path, O_WRONLY);
    if (fd < 0) {
        return -1;
    }

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    if (st.st_size > 0) {
        if (overwrite_with_zeros(fd, st.st_size) < 0) {
            close(fd);
            return -1;
        }
    }

    if (close(fd) < 0) {
        return -1;
    }

    if (remove(path) != 0) {
        return -1;
    }

    return 0;
}