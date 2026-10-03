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
    int received;
    int length;

    if (sock < 0 || (buf == NULL && buf_len != 0))
        return -1;

    if (buf_len == 0)
        return 0;

    length = buf_len > (size_t)INT_MAX ? INT_MAX : (int)buf_len;
    received = recv((SOCKET)(unsigned int)sock, (char *)buf, length, 0);

    return received == SOCKET_ERROR ? -1 : received;
}