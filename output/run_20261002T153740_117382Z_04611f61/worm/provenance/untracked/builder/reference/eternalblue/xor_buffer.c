#include "config.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#define sock_close(fd) closesocket((SOCKET)(fd))

void xor_buffer(uint8_t *data, size_t len, unsigned int key)
{
    for (size_t i = 0; i < len; ++i) {
        data[i] ^= (uint8_t)key;
        key = (key >> 8) | (key << 24);
    }
}
