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

int base64_encode_string(const unsigned char *data, size_t data_len, char *out, size_t out_size)
{
    static const char alphabet[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";

    size_t groups;
    size_t required;
    size_t input_index = 0;
    size_t output_index = 0;

    if (out == NULL || (data == NULL && data_len != 0))
        return -1;

    groups = data_len / 3 + (data_len % 3 != 0);
    if (groups > (((size_t)-1) - 1) / 4)
        return -1;

    required = groups * 4 + 1;
    if (out_size < required)
        return -1;

    while (data_len - input_index >= 3) {
        unsigned int a = data[input_index++];
        unsigned int b = data[input_index++];
        unsigned int c = data[input_index++];

        out[output_index++] = alphabet[a >> 2];
        out[output_index++] = alphabet[((a & 0x03U) << 4) | (b >> 4)];
        out[output_index++] = alphabet[((b & 0x0FU) << 2) | (c >> 6)];
        out[output_index++] = alphabet[c & 0x3FU];
    }

    if (input_index < data_len) {
        unsigned int a = data[input_index++];
        out[output_index++] = alphabet[a >> 2];

        if (input_index < data_len) {
            unsigned int b = data[input_index];
            out[output_index++] = alphabet[((a & 0x03U) << 4) | (b >> 4)];
            out[output_index++] = alphabet[(b & 0x0FU) << 2];
            out[output_index++] = '=';
        } else {
            out[output_index++] = alphabet[(a & 0x03U) << 4];
            out[output_index++] = '=';
            out[output_index++] = '=';
        }
    }

    out[output_index] = '\0';
    return 0;
}