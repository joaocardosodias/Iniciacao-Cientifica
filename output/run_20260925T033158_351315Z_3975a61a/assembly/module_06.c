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
#include <errno.h>
#include <string.h>

static int write_zeros(int fd, off_t size) {
    const size_t bufsize = 4096;
    char buf[bufsize];
    memset(buf, 0, bufsize);
    while (size > 0) {
        ssize_t chunk = size > (off_t)bufsize ? (ssize_t)bufsize : (ssize_t)size;
        ssize_t written = 0;
        while (written < chunk) {
            ssize_t res = write(fd, buf + written, (size_t)(chunk - written));
            if (res < 0) {
                if (errno == EINTR)
                    continue;
                return -1;
            }
            written += res;
        }
        size -= chunk;
    }
    return 0;
}

int secure_erase(const char *path) {
    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    if (write_zeros(fd, st.st_size) < 0) {
        close(fd);
        return -1;
    }

    if (fsync(fd) < 0) {
        close(fd);
        return -1;
    }

    if (close(fd) < 0)
        return -1;

    if (remove(path) != 0)
        return -1;

    return 0;
}