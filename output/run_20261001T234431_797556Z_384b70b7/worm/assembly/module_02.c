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

    size_t full_groups;
    size_t remainder;
    size_t encoded_len;
    size_t i;
    size_t j = 0;

    if (out == NULL || (data == NULL && data_len != 0))
        return -1;

    full_groups = data_len / 3;
    remainder = data_len % 3;

    if (full_groups > (SIZE_MAX - 1 - (remainder != 0 ? 4 : 0)) / 4)
        return -1;

    encoded_len = full_groups * 4 + (remainder != 0 ? 4 : 0);
    if (out_size < encoded_len + 1)
        return -1;

    for (i = 0; i < full_groups; ++i) {
        unsigned int a = data[i * 3];
        unsigned int b = data[i * 3 + 1];
        unsigned int c = data[i * 3 + 2];

        out[j++] = alphabet[a >> 2];
        out[j++] = alphabet[((a & 0x03U) << 4) | (b >> 4)];
        out[j++] = alphabet[((b & 0x0FU) << 2) | (c >> 6)];
        out[j++] = alphabet[c & 0x3FU];
    }

    if (remainder != 0) {
        size_t offset = full_groups * 3;
        unsigned int a = data[offset];

        out[j++] = alphabet[a >> 2];

        if (remainder == 2) {
            unsigned int b = data[offset + 1];
            out[j++] = alphabet[((a & 0x03U) << 4) | (b >> 4)];
            out[j++] = alphabet[(b & 0x0FU) << 2];
        } else {
            out[j++] = alphabet[(a & 0x03U) << 4];
            out[j++] = '=';
        }

        out[j++] = '=';
    }

    out[j] = '\0';
    return 0;
}