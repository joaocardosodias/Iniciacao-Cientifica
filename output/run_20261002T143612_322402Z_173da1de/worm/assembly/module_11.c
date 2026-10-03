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
    SOCKET socket_handle;

    if (buf_len > (size_t)INT_MAX) {
        recv_len = INT_MAX;
    } else {
        recv_len = (int)buf_len;
    }

    socket_handle = (SOCKET)(uintptr_t)(unsigned int)sock;
    result = recv(socket_handle, (char *)buf, recv_len, 0);

    return result == SOCKET_ERROR ? -1 : result;
}