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
#include <errno.h>
#include <fcntl.h>
#include <sys/stat.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    unsigned char zeros[65536] = {0};
    struct stat st;
    off_t remaining;
    int fd;
    int saved_errno = 0;

    fd = open(path, O_WRONLY);
    if (fd == -1)
        return -1;

    if (fstat(fd, &st) == -1) {
        saved_errno = errno;
    } else if (st.st_size < 0) {
        saved_errno = EIO;
    } else {
        remaining = st.st_size;
        while (remaining > 0) {
            size_t count = remaining < (off_t)sizeof(zeros)
                               ? (size_t)remaining
                               : sizeof(zeros);
            ssize_t written = write(fd, zeros, count);

            if (written == -1 && errno == EINTR)
                continue;
            if (written <= 0) {
                saved_errno = written == 0 ? EIO : errno;
                break;
            }
            remaining -= written;
        }
    }

    if (close(fd) == -1 && saved_errno == 0)
        saved_errno = errno;

    if (saved_errno != 0) {
        errno = saved_errno;
        return -1;
    }

    return remove(path);
}