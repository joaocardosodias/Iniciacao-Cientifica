#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <limits.h>

static INIT_ONCE smb_winsock_once = INIT_ONCE_STATIC_INIT;

static BOOL CALLBACK smb_initialize_winsock(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
    WSADATA data;
    (void)once;
    (void)parameter;
    (void)context;
    return WSAStartup(MAKEWORD(2, 2), &data) == 0;
}

int smb_connect(const char *ip, int port)
{
    struct sockaddr_in address;
    SOCKET sock;
    DWORD timeout_ms = 2000;

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

    if (!InitOnceExecuteOnce(&smb_winsock_once, smb_initialize_winsock, NULL, NULL))
        return -1;

    ZeroMemory(&address, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);

    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1)
        return -1;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        return -1;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms,
                   (int)sizeof(timeout_ms)) == SOCKET_ERROR ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms,
                   (int)sizeof(timeout_ms)) == SOCKET_ERROR ||
        connect(sock, (const struct sockaddr *)&address, (int)sizeof(address)) == SOCKET_ERROR ||
        sock > (SOCKET)INT_MAX) {
        closesocket(sock);
        return -1;
    }

    return (int)sock;
}