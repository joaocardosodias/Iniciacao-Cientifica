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
#include <ws2tcpip.h>
#include <windows.h>
#include <limits.h>
#include <string.h>

static INIT_ONCE smb_winsock_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK smb_winsock_initialize(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
    WSADATA data;
    (void)once;
    (void)parameter;
    (void)context;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
}

int smb_connect(const char *ip, int port)
{
    struct sockaddr_storage address;
    int address_length;
    int family;
    SOCKET sock;
    DWORD timeout_ms = 2000;

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

    if (!InitOnceExecuteOnce(&smb_winsock_once, smb_winsock_initialize, NULL, NULL))
        return -1;

    memset(&address, 0, sizeof(address));

    if (InetPtonA(AF_INET, ip, &((struct sockaddr_in *)&address)->sin_addr) == 1) {
        struct sockaddr_in *address4 = (struct sockaddr_in *)&address;
        family = AF_INET;
        address4->sin_family = AF_INET;
        address4->sin_port = htons((u_short)port);
        address_length = (int)sizeof(*address4);
    } else if (InetPtonA(AF_INET6, ip, &((struct sockaddr_in6 *)&address)->sin6_addr) == 1) {
        struct sockaddr_in6 *address6 = (struct sockaddr_in6 *)&address;
        family = AF_INET6;
        address6->sin6_family = AF_INET6;
        address6->sin6_port = htons((u_short)port);
        address_length = (int)sizeof(*address6);
    } else {
        return -1;
    }

    sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        return -1;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms,
                   (int)sizeof(timeout_ms)) == SOCKET_ERROR ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms,
                   (int)sizeof(timeout_ms)) == SOCKET_ERROR ||
        connect(sock, (const struct sockaddr *)&address, address_length) == SOCKET_ERROR ||
        (UINT_PTR)sock > (UINT_PTR)INT_MAX) {
        closesocket(sock);
        return -1;
    }

    return (int)sock;
}