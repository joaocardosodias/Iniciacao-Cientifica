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
#include <sys/types.h>
#include <errno.h>

static ssize_t write_all(int fd, const void *buf, size_t count) {
    const char *p = buf;
    size_t left = count;
    while (left > 0) {
        ssize_t w = write(fd, p, left);
        if (w < 0) {
            if (errno == EINTR) continue;
            return -1;
        }
        if (w == 0) {
            return -1;
        }
        p += w;
        left -= w;
    }
    return (ssize_t)count;
}

int secure_erase(const char *path) {
    if (!path) return -1;

    int fd = open(path, O_WRONLY);
    if (fd == -1) return -1;

    struct stat st;
    if (fstat(fd, &st) == -1) {
        close(fd);
        return -1;
    }

    off_t size = st.st_size;
    if (size > 0) {
        const size_t blk = 4096;
        static const char zeros[4096] = {0};
        off_t written = 0;
        while (written < size) {
            size_t to_write = (size - written) < (off_t)blk ? (size_t)(size - written) : blk;
            if (write_all(fd, zeros, to_write) == -1) {
                close(fd);
                return -1;
            }
            written += to_write;
        }
        if (fsync(fd) == -1) {
            close(fd);
            return -1;
        }
    }

    if (close(fd) == -1) {
        remove(path);
        return -1;
    }

    if (remove(path) != 0) return -1;
    return 0;
}