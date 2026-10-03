#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <limits.h>
#include <math.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <stddef.h>
#include <stdint.h>

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    size_t groups;
    size_t remainder;
    size_t encoded_len;
    size_t required;
    size_t i = 0;
    size_t j = 0;
    size_t max_size = (size_t)-1;

    if (out == NULL || (data == NULL && data_len != 0))
        return -1;

    groups = data_len / 3;
    remainder = data_len % 3;

    if (groups > (max_size - 1 - (remainder != 0 ? 4 : 0)) / 4)
        return -1;

    encoded_len = groups * 4 + (remainder != 0 ? 4 : 0);
    required = encoded_len + 1;

    if (out_size < required)
        return -1;

    while (i < data_len) {
        unsigned int a = data[i++];
        unsigned int b = i < data_len ? data[i++] : 0;
        unsigned int c = i < data_len ? data[i++] : 0;

        out[j++] = alphabet[a >> 2];
        out[j++] = alphabet[((a & 0x03U) << 4) | (b >> 4)];
        out[j++] = alphabet[((b & 0x0FU) << 2) | (c >> 6)];
        out[j++] = alphabet[c & 0x3FU];
    }

    if (remainder == 1)
        out[encoded_len - 2] = '=';
    if (remainder != 0)
        out[encoded_len - 1] = '=';

    out[encoded_len] = '\0';
    return 0;
}