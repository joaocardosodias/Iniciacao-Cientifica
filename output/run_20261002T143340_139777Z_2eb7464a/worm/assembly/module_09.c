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
    struct sockaddr_in address;
    DWORD timeout_ms = 2000;

    if (ip == NULL || port < 1 || port > 65535) {
        return -1;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return -1;
    }

    if (sock > (SOCKET)INT_MAX) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                   (const char *)&timeout_ms, (int)sizeof(timeout_ms)) == SOCKET_ERROR ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                   (const char *)&timeout_ms, (int)sizeof(timeout_ms)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    ZeroMemory(&address, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);

    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1 ||
        connect(sock, (const struct sockaddr *)&address, (int)sizeof(address)) == SOCKET_ERROR) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    return (int)sock;
}