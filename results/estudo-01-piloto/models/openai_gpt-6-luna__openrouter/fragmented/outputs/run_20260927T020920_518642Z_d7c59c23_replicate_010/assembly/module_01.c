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
#include <limits.h>
#include <stddef.h>
#include <openssl/rand.h>

int random_bytes(unsigned char *out, size_t len)
{
    if (len == 0)
        return 0;
    if (out == NULL)
        return -1;

    while (len > 0) {
        int chunk = len > (size_t)INT_MAX ? INT_MAX : (int)len;
        if (RAND_bytes(out, chunk) != 1)
            return -1;
        out += chunk;
        len -= (size_t)chunk;
    }

    return 0;
}