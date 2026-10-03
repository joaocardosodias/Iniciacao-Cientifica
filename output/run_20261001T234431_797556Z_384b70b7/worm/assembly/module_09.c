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
#include <windows.h>
#include <ws2tcpip.h>
#include <limits.h>
#include <string.h>

static INIT_ONCE smb_wsa_once = INIT_ONCE_STATIC_INIT;
static int smb_wsa_status = WSASYSNOTREADY;

static BOOL CALLBACK smb_wsa_initialize(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
    WSADATA data;
    (void)once;
    (void)parameter;
    (void)context;

    smb_wsa_status = WSAStartup(MAKEWORD(2, 2), &data);
    return smb_wsa_status == 0;
}

int smb_connect(const char *ip, int port)
{
    struct sockaddr_storage address;
    int address_length;
    int family;
    SOCKET socket_handle;
    DWORD timeout_ms = 2000;

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

    if (!InitOnceExecuteOnce(&smb_wsa_once, smb_wsa_initialize, NULL, NULL) ||
        smb_wsa_status != 0)
        return -1;

    memset(&address, 0, sizeof(address));

    if (InetPtonA(AF_INET, ip, &((struct sockaddr_in *)&address)->sin_addr) == 1) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&address;
        family = AF_INET;
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons((u_short)port);
        address_length = (int)sizeof(*ipv4);
    } else if (InetPtonA(AF_INET6, ip, &((struct sockaddr_in6 *)&address)->sin6_addr) == 1) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&address;
        family = AF_INET6;
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons((u_short)port);
        address_length = (int)sizeof(*ipv6);
    } else {
        return -1;
    }

    socket_handle = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (socket_handle == INVALID_SOCKET)
        return -1;

    if (setsockopt(socket_handle, SOL_SOCKET, SO_RCVTIMEO,
                   (const char *)&timeout_ms, (int)sizeof(timeout_ms)) == SOCKET_ERROR ||
        setsockopt(socket_handle, SOL_SOCKET, SO_SNDTIMEO,
                   (const char *)&timeout_ms, (int)sizeof(timeout_ms)) == SOCKET_ERROR ||
        connect(socket_handle, (const struct sockaddr *)&address, address_length) == SOCKET_ERROR) {
        closesocket(socket_handle);
        return -1;
    }

    if ((unsigned long long)socket_handle > INT_MAX) {
        closesocket(socket_handle);
        return -1;
    }

    return (int)socket_handle;
}