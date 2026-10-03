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
#include <stdint.h>
#include <stddef.h>

void xor_buffer(uint8_t *data, size_t len, unsigned int key)
{
    size_t i;

    for (i = 0; i < len; ++i) {
        data[i] ^= (uint8_t)key;
        key = (key >> 8) | (key << 24);
    }
}