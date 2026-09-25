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
#include <sys/stat.h>
#include <unistd.h>
#include <errno.h>

int secure_erase(const char *path)
{
    unsigned char zeros[65536] = {0};
    struct stat st;
    off_t offset = 0;
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    int failed = 0;

    if (fd < 0)
        return -1;

    if (fstat(fd, &st) < 0 || st.st_size < 0) {
        failed = 1;
    } else {
        while (offset < st.st_size) {
            off_t remaining = st.st_size - offset;
            size_t length = remaining < (off_t)sizeof(zeros)
                                ? (size_t)remaining
                                : sizeof(zeros);
            ssize_t written = pwrite(fd, zeros, length, offset);

            if (written < 0 && errno == EINTR)
                continue;
            if (written <= 0) {
                failed = 1;
                break;
            }
            offset += written;
        }
    }

    if (close(fd) < 0)
        failed = 1;

    if (failed)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}