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

static INIT_ONCE smb_wsa_once = INIT_ONCE_STATIC_INIT;
static int smb_wsa_error;

static BOOL CALLBACK smb_initialize_winsock(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
    WSADATA data;
    (void)once;
    (void)parameter;
    (void)context;

    smb_wsa_error = WSAStartup(MAKEWORD(2, 2), &data);
    return smb_wsa_error == 0;
}

int smb_connect(const char *ip, int port)
{
    SOCKET sock;
    struct sockaddr_in address;
    DWORD timeout_ms = 2000;

    if (ip == NULL || port < 1 || port > 65535) {
        return -1;
    }

    if (!InitOnceExecuteOnce(&smb_wsa_once, smb_initialize_winsock, NULL, NULL)) {
        return -1;
    }

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    if (sock > (SOCKET)INT_MAX) {
        closesocket(sock);
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                   (const char *)&timeout_ms, (int)sizeof(timeout_ms)) == SOCKET_ERROR ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                   (const char *)&timeout_ms, (int)sizeof(timeout_ms)) == SOCKET_ERROR) {
        closesocket(sock);
        return -1;
    }

    ZeroMemory(&address, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);

    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1) {
        closesocket(sock);
        return -1;
    }

    if (connect(sock, (const struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR) {
        closesocket(sock);
        return -1;
    }

    return (int)sock;
}