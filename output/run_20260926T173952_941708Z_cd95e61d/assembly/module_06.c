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
#include <sys/types.h>

int secure_erase(const char *path)
{
    FILE *file;
    off_t length = 0;
    off_t remaining;
    unsigned char zeros[8192] = {0};
    int failed = 0;

    if (path == NULL)
        return -1;

    file = fopen(path, "r+b");
    if (file == NULL)
        return -1;

    if (fseeko(file, 0, SEEK_END) != 0) {
        failed = 1;
    } else {
        length = ftello(file);
        if (length < 0)
            failed = 1;
    }

    if (!failed && fseeko(file, 0, SEEK_SET) != 0)
        failed = 1;

    remaining = length;
    while (!failed && remaining > 0) {
        size_t count = remaining > (off_t)sizeof(zeros)
                           ? sizeof(zeros)
                           : (size_t)remaining;

        if (fwrite(zeros, 1, count, file) != count) {
            failed = 1;
            break;
        }
        remaining -= (off_t)count;
    }

    if (fflush(file) != 0)
        failed = 1;
    if (fclose(file) != 0)
        failed = 1;

    if (failed)
        return -1;

    return remove(path) == 0 ? 0 : -1;
}