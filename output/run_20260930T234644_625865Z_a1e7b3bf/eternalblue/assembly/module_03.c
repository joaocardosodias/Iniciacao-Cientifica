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
#include <winsock2.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>

int smb_recv(int sock, uint8_t *buf, size_t buf_len)
{
    int recv_len;
    int result;

    if (sock < 0 || (buf == NULL && buf_len != 0)) {
        return -1;
    }

    recv_len = buf_len > (size_t)INT_MAX ? INT_MAX : (int)buf_len;
    result = recv((SOCKET)(uintptr_t)(unsigned int)sock, (char *)buf, recv_len, 0);
    if (result == SOCKET_ERROR) {
        return -1;
    }

    return result;
}