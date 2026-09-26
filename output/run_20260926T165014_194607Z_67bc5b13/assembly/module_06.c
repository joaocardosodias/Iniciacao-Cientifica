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
#include <unistd.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <stdio.h>
#include <errno.h>
#include <string.h>

static ssize_t full_write(int fd, const void *buf, size_t count) {
    const char *ptr = (const char *)buf;
    size_t left = count;
    while (left > 0) {
        ssize_t written = write(fd, ptr, left);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        left -= (size_t)written;
        ptr += written;
    }
    return (ssize_t)count;
}

int secure_erase(const char *path) {
    if (!path) {
        errno = EINVAL;
        return -1;
    }

    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    size_t size = (size_t)st.st_size;
    static const char zero_buf[4096] = {0};
    size_t offset = 0;

    while (offset < size) {
        size_t chunk = size - offset;
        if (chunk > sizeof(zero_buf))
            chunk = sizeof(zero_buf);
        if (full_write(fd, zero_buf, chunk) < 0) {
            close(fd);
            return -1;
        }
        offset += chunk;
    }

    if (fsync(fd) < 0) {
        close(fd);
        return -1;
    }

    if (close(fd) < 0)
        return -1;

    if (remove(path) < 0)
        return -1;

    return 0;
}