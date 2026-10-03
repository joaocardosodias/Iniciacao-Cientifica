#include <winsock2.h>
#include <ws2tcpip.h>
#include <limits.h>

static INIT_ONCE smb_wsa_once = INIT_ONCE_STATIC_INIT;
static int smb_wsa_status = WSASYSNOTREADY;

static BOOL CALLBACK smb_wsa_initialize(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
    WSADATA data;
    int status;

    (void)once;
    (void)parameter;
    (void)context;

    status = WSAStartup(MAKEWORD(2, 2), &data);
    if (status == 0) {
        if (LOBYTE(data.wVersion) == 2 && HIBYTE(data.wVersion) == 2) {
            smb_wsa_status = 0;
        } else {
            WSACleanup();
            smb_wsa_status = WSAVERNOTSUPPORTED;
        }
    } else {
        smb_wsa_status = status;
    }

    return TRUE;
}

int smb_connect(const char *ip, int port)
{
    struct sockaddr_storage address;
    int address_length;
    int family;
    SOCKET sock;
    DWORD timeout_ms = 2000;
    int status;

    if (ip == NULL || port < 1 || port > 65535) {
        return -1;
    }

    if (!InitOnceExecuteOnce(&smb_wsa_once, smb_wsa_initialize, NULL, NULL) ||
        smb_wsa_status != 0) {
        return -1;
    }

    ZeroMemory(&address, sizeof(address));

    if (InetPtonA(AF_INET, ip, &((struct sockaddr_in *)&address)->sin_addr) == 1) {
        struct sockaddr_in *ipv4 = (struct sockaddr_in *)&address;
        family = AF_INET;
        address_length = (int)sizeof(*ipv4);
        ipv4->sin_family = AF_INET;
        ipv4->sin_port = htons((u_short)port);
    } else if (InetPtonA(AF_INET6, ip, &((struct sockaddr_in6 *)&address)->sin6_addr) == 1) {
        struct sockaddr_in6 *ipv6 = (struct sockaddr_in6 *)&address;
        family = AF_INET6;
        address_length = (int)sizeof(*ipv6);
        ipv6->sin6_family = AF_INET6;
        ipv6->sin6_port = htons((u_short)port);
    } else {
        return -1;
    }

    sock = socket(family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    status = setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms,
                        (int)sizeof(timeout_ms));
    if (status == SOCKET_ERROR) {
        closesocket(sock);
        return -1;
    }

    status = setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms,
                        (int)sizeof(timeout_ms));
    if (status == SOCKET_ERROR) {
        closesocket(sock);
        return -1;
    }

    if (connect(sock, (const struct sockaddr *)&address, address_length) == SOCKET_ERROR) {
        closesocket(sock);
        return -1;
    }

    if (sock > (SOCKET)INT_MAX) {
        closesocket(sock);
        return -1;
    }

    return (int)sock;
}