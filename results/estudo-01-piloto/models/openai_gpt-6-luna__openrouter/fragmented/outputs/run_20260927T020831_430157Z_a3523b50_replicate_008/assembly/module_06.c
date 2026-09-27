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
#include <stdio.h>

int secure_erase(const char *path)
{
    unsigned char zeros[65536] = {0};
    struct stat st;
    off_t offset = 0;
    int fd;

    do {
        fd = open(path, O_WRONLY | O_CLOEXEC);
    } while (fd == -1 && errno == EINTR);
    if (fd == -1)
        return -1;

    if (fstat(fd, &st) == -1 || st.st_size < 0) {
        int saved_errno = errno;
        if (st.st_size < 0)
            saved_errno = EINVAL;
        close(fd);
        errno = saved_errno;
        return -1;
    }

    while (offset < st.st_size) {
        off_t remaining = st.st_size - offset;
        size_t chunk = remaining < (off_t)sizeof(zeros)
                           ? (size_t)remaining
                           : sizeof(zeros);
        ssize_t written;

        do {
            written = pwrite(fd, zeros, chunk, offset);
        } while (written == -1 && errno == EINTR);

        if (written <= 0) {
            int saved_errno = written == 0 ? EIO : errno;
            close(fd);
            errno = saved_errno;
            return -1;
        }
        offset += written;
    }

    if (close(fd) == -1)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}