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

int smb_connect(const char *ip, int port)
{
    static volatile LONG winsock_state = 0;
    LONG state;
    WSADATA wsa_data;
    SOCKET sock;
    DWORD timeout_ms = 2000;
    struct sockaddr_in addr4;
    struct sockaddr_in6 addr6;
    const struct sockaddr *address;
    int address_length;
    int family;

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

    state = InterlockedCompareExchange(&winsock_state, 1, 0);
    if (state == 0) {
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)
            InterlockedExchange(&winsock_state, 2);
        else
            InterlockedExchange(&winsock_state, -1);
    } else {
        while (state == 1) {
            Sleep(1);
            state = InterlockedCompareExchange(&winsock_state, 0, 0);
        }
    }

    if (InterlockedCompareExchange(&winsock_state, 0, 0) != 2)
        return -1;

    if (InetPtonA(AF_INET, ip, &addr4.sin_addr) == 1) {
        addr4.sin_family = AF_INET;
        addr4.sin_port = htons((u_short)port);
        address = (const struct sockaddr *)&addr4;
        address_length = (int)sizeof(addr4);
        family = AF_INET;
    } else if (InetPtonA(AF_INET6, ip, &addr6.sin6_addr) == 1) {
        addr6.sin6_family = AF_INET6;
        addr6.sin6_port = htons((u_short)port);
        addr6.sin6_flowinfo = 0;
        addr6.sin6_scope_id = 0;
        address = (const struct sockaddr *)&addr6;
        address_length = (int)sizeof(addr6);
        family = AF_INET6;
    } else {
        return -1;
    }

    sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        return -1;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                   (const char *)&timeout_ms, (int)sizeof(timeout_ms)) == SOCKET_ERROR ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                   (const char *)&timeout_ms, (int)sizeof(timeout_ms)) == SOCKET_ERROR ||
        connect(sock, address, address_length) == SOCKET_ERROR ||
        sock > (SOCKET)INT_MAX) {
        closesocket(sock);
        return -1;
    }

    return (int)sock;
}