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
    WSADATA wsa_data;
    struct sockaddr_storage address;
    int address_length;
    int family;
    SOCKET sock;
    DWORD timeout_ms = 2000;

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

    for (;;) {
        LONG state = InterlockedCompareExchange(&winsock_state, 0, 0);
        if (state == 2)
            break;
        if (state == 0 &&
            InterlockedCompareExchange(&winsock_state, 1, 0) == 0) {
            if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
                InterlockedExchange(&winsock_state, 0);
                return -1;
            }
            InterlockedExchange(&winsock_state, 2);
            break;
        }
        Sleep(0);
    }

    ZeroMemory(&address, sizeof(address));
    if (InetPtonA(AF_INET, ip, &((struct sockaddr_in *)&address)->sin_addr) == 1) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&address;
        family = AF_INET;
        address_length = sizeof(*ipv4);
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons((u_short)port);
    } else if (InetPtonA(AF_INET6, ip, &((struct sockaddr_in6 *)&address)->sin6_addr) == 1) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&address;
        family = AF_INET6;
        address_length = sizeof(*ipv6);
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons((u_short)port);
    } else {
        return -1;
    }

    sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        return -1;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms,
                   sizeof(timeout_ms)) == SOCKET_ERROR ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms,
                   sizeof(timeout_ms)) == SOCKET_ERROR ||
        connect(sock, (const struct sockaddr *)&address, address_length) == SOCKET_ERROR ||
        (UINT_PTR)sock > (UINT_PTR)INT_MAX) {
        closesocket(sock);
        return -1;
    }

    return (int)sock;
}