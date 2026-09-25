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
#include <stdio.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    int fd;
    struct stat st;
    off_t remaining;
    char buf[4096];

    if (path == NULL)
        return -1;

    fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0) {
        close(fd);
        return -1;
    }

    if (!S_ISREG(st.st_mode)) {
        close(fd);
        return -1;
    }

    memset(buf, 0, sizeof(buf));
    remaining = st.st_size;
    while (remaining > 0) {
        size_t chunk;
        ssize_t n;

        chunk = remaining > (off_t)sizeof(buf) ? sizeof(buf) : (size_t)remaining;
        do {
            n = write(fd, buf, chunk);
        } while (n < 0 && errno == EINTR);
        if (n <= 0) {
            close(fd);
            return -1;
        }
        remaining -= n;
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