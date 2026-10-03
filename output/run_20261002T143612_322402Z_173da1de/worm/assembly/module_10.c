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

int smb_send(int sock, const uint8_t *data, size_t len)
{
    size_t sent = 0;

    if (len != 0 && data == NULL)
        return -1;

    while (sent < len) {
        size_t remaining = len - sent;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = send((SOCKET)sock, (const char *)data + sent, chunk, 0);

        if (result == SOCKET_ERROR || result == 0)
            return -1;

        sent += (size_t)result;
    }

    return 0;
}