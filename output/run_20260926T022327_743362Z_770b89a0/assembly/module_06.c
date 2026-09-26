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
#include <sys/stat.h>
#include <unistd.h>

int secure_erase(const char *path)
{
    static const unsigned char zeros[65536] = {0};
    struct stat st;
    int fd = open(path, O_WRONLY | O_CLOEXEC);
    if (fd == -1)
        return -1;

    int result = 0;
    if (fstat(fd, &st) == -1 || st.st_size < 0) {
        result = -1;
    } else {
        off_t offset = 0;
        off_t remaining = st.st_size;

        while (remaining > 0) {
            size_t amount = remaining > (off_t)sizeof(zeros)
                                ? sizeof(zeros)
                                : (size_t)remaining;
            ssize_t written = pwrite(fd, zeros, amount, offset);

            if (written == -1 && errno == EINTR)
                continue;
            if (written <= 0) {
                result = -1;
                break;
            }

            offset += written;
            remaining -= written;
        }
    }

    if (close(fd) == -1)
        result = -1;
    if (result == -1)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}