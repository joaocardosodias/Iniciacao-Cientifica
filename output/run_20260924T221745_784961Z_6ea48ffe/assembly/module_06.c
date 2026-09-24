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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>

int secure_erase(const char *path)
{
    struct stat st;
    int fd;
    off_t file_size;
    off_t written;
    ssize_t ret;
    unsigned char buf[4096];
    size_t to_write;

    if (stat(path, &st) != 0)
        return -1;

    file_size = st.st_size;

    fd = open(path, O_WRONLY);
    if (fd < 0)
        return -1;

    memset(buf, 0, sizeof(buf));

    written = 0;
    while (written < file_size) {
        to_write = sizeof(buf);
        if ((off_t)to_write > file_size - written)
            to_write = (size_t)(file_size - written);

        ret = write(fd, buf, to_write);
        if (ret < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return -1;
        }
        if (ret == 0) {
            close(fd);
            return -1;
        }
        written += ret;
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