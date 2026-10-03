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

void xor_buffer(uint8_t *data, size_t len, unsigned int key)
{
    uint32_t rotating_key = (uint32_t)key;

    for (size_t i = 0; i < len; ++i) {
        data[i] ^= (uint8_t)rotating_key;
        rotating_key = (rotating_key >> 8) | (rotating_key << 24);
    }
}