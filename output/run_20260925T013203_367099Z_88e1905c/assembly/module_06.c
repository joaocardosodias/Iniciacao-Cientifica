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
#include <errno.h>

static int overwrite_with_zeros(int fd, off_t length) {
    static const char zero_buf[4096] = {0};
    off_t offset = 0;
    while (offset < length) {
        size_t to_write = (size_t)((length - offset) < (off_t)sizeof(zero_buf) ? (length - offset) : sizeof(zero_buf));
        ssize_t written = write(fd, zero_buf, to_write);
        if (written <= 0) {
            return -1;
        }
        offset += written;
    }
    return 0;
}

int secure_erase(const char *path) {
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