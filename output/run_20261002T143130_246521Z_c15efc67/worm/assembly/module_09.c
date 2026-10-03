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
#include <limits.h>

int smb_connect(const char *ip, int port)
{
    WSADATA wsa_data;
    SOCKET sock;
    DWORD timeout_ms = 2000;
    int family;
    int result;

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return -1;

    struct sockaddr_storage address;
    int address_length;

    if (InetPtonA(AF_INET, ip, &((struct sockaddr_in *)&address)->sin_addr) == 1) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&address;
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons((u_short)port);
        family = AF_INET;
        address_length = (int)sizeof(*ipv4);
    } else if (InetPtonA(AF_INET6, ip, &((struct sockaddr_in6 *)&address)->sin6_addr) == 1) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&address;
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons((u_short)port);
        family = AF_INET6;
        address_length = (int)sizeof(*ipv6);
    } else {
        WSACleanup();
        return -1;
    }

    sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms,
                   (int)sizeof(timeout_ms)) == SOCKET_ERROR ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms,
                   (int)sizeof(timeout_ms)) == SOCKET_ERROR ||
        connect(sock, (const struct sockaddr *)&address, address_length) == SOCKET_ERROR ||
        (UINT_PTR)sock > (UINT_PTR)INT_MAX) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    result = (int)sock;
    return result;
}