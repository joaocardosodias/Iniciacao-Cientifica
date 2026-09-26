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

int secure_erase(const char *path)
{
    struct stat st;
    if (stat(path, &st) != 0)
        return -1;

    off_t size = st.st_size;
    int fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;

    const size_t bufsize = 4096;
    static const char zero_buf[4096] = {0};

    off_t written = 0;
    while (written < size) {
        size_t to_write = (size - written) < (off_t)bufsize ? (size_t)(size - written) : bufsize;
        ssize_t res = write(fd, zero_buf, to_write);
        if (res <= 0) {
            close(fd);
            return -1;
        }
        written += res;
    }

    if (fsync(fd) != 0) {
        close(fd);
        return -1;
    }

    if (close(fd) != 0)
        return -1;

    if (remove(path) != 0)
        return -1;

    return 0;
}