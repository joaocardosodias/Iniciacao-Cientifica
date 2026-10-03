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
#include <string.h>

int smb_connect(const char *ip, int port)
{
    WSADATA wsa_data;
    SOCKET sock;
    struct sockaddr_storage address;
    int address_length;
    int timeout_ms = 2000;
    int startup_result;

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

    startup_result = WSAStartup(MAKEWORD(2, 2), &wsa_data);
    if (startup_result != 0)
        return -1;

    memset(&address, 0, sizeof(address));

    {
        struct sockaddr_in *address4 = (struct sockaddr_in *)&address;
        struct sockaddr_in6 *address6 = (struct sockaddr_in6 *)&address;

        if (InetPtonA(AF_INET, ip, &address4->sin_addr) == 1) {
            address4->sin_family = AF_INET;
            address4->sin_port = htons((u_short)port);
            address_length = (int)sizeof(*address4);
            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        } else if (InetPtonA(AF_INET6, ip, &address6->sin6_addr) == 1) {
            address6->sin6_family = AF_INET6;
            address6->sin6_port = htons((u_short)port);
            address_length = (int)sizeof(*address6);
            sock = socket(AF_INET6, SOCK_STREAM, IPPROTO_TCP);
        } else {
            WSACleanup();
            return -1;
        }
    }

    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return -1;
    }

    if (sock > (SOCKET)INT_MAX ||
        setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms,
                   (int)sizeof(timeout_ms)) == SOCKET_ERROR ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms,
                   (int)sizeof(timeout_ms)) == SOCKET_ERROR ||
        connect(sock, (const struct sockaddr *)&address, address_length) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    return (int)sock;
}