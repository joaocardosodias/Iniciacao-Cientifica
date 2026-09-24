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
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    const unsigned char empty = 0;
    size_t groups;
    size_t encoded_len;
    int result;

    if (out == NULL || (data == NULL && data_len != 0) || data_len > INT_MAX)
        return -1;

    groups = data_len / 3 + (data_len % 3 != 0);
    if (groups > INT_MAX / 4)
        return -1;

    encoded_len = groups * 4;
    if (out_size <= encoded_len)
        return -1;

    if (data == NULL)
        data = &empty;

    result = EVP_EncodeBlock((unsigned char *)out, data, (int)data_len);
    return result == (int)encoded_len ? 0 : -1;
}