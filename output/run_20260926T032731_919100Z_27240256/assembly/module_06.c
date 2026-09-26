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
             
            goto cleanup_fd;
        }
        to_write -= written;
    }

     
    if (fsync(fd) < 0)
        goto cleanup_fd;

    if (close(fd) < 0)
        return -1;
    fd = -1;  

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