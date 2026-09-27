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
#include <stdint.h>
#include <stddef.h>
#include <openssl/evp.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    size_t groups;
    size_t encoded_len;
    size_t remaining;
    size_t input_offset = 0;
    size_t output_offset = 0;
    const size_t max_chunk = ((size_t)INT_MAX / 4) * 3;

    if (out == NULL || (data_len != 0 && data == NULL))
        return -1;

    groups = data_len / 3 + (data_len % 3 != 0);
    if (groups > (SIZE_MAX - 1) / 4)
        return -1;

    encoded_len = groups * 4;
    if (out_size < encoded_len + 1)
        return -1;

    remaining = data_len;
    while (remaining > max_chunk) {
        int written = EVP_EncodeBlock((unsigned char *)out + output_offset,
                                      data + input_offset, (int)max_chunk);
        if (written != (int)(max_chunk / 3 * 4))
            return -1;
        input_offset += max_chunk;
        output_offset += (size_t)written;
        remaining -= max_chunk;
    }

    if (remaining != 0) {
        int written = EVP_EncodeBlock((unsigned char *)out + output_offset,
                                      data + input_offset, (int)remaining);
        if (written < 0 || (size_t)written != remaining / 3 * 4 +
                                             (remaining % 3 != 0) * 4)
            return -1;
        output_offset += (size_t)written;
    }

    out[output_offset] = '\0';
    return 0;
}