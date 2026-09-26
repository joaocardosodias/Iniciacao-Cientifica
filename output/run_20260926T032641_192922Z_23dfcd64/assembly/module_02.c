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
    unsigned char empty_input = 0;
    size_t encoded_len;
    int result;

    if (out == NULL || (data == NULL && data_len != 0) ||
        data_len > (size_t)INT_MAX) {
        return -1;
    }

    encoded_len = (data_len / 3) * 4 + (data_len % 3 == 0 ? 0 : 4);
    if (encoded_len > (size_t)INT_MAX || out_size < encoded_len + 1) {
        return -1;
    }

    result = EVP_EncodeBlock((unsigned char *)out,
                             data != NULL ? data : &empty_input,
                             (int)data_len);
    if (result < 0 || (size_t)result != encoded_len) {
        return -1;
    }

    out[encoded_len] = '\0';
    return 0;
}