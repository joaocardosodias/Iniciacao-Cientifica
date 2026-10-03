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
    int address_family;
    DWORD timeout_ms = 2000;

    if (ip == NULL || port < 0 || port > 65535)
        return -1;

    memset(&address, 0, sizeof(address));

    {
        struct sockaddr_in *address4 = (struct sockaddr_in *)&address;
        if (InetPtonA(AF_INET, ip, &address4->sin_addr) == 1) {
            address4->sin_family = AF_INET;
            address4->sin_port = htons((u_short)port);
            address_family = AF_INET;
            address_length = sizeof(*address4);
        } else {
            struct sockaddr_in6 *address6 = (struct sockaddr_in6 *)&address;
            if (InetPtonA(AF_INET6, ip, &address6->sin6_addr) != 1)
                return -1;
            address6->sin6_family = AF_INET6;
            address6->sin6_port = htons((u_short)port);
            address_family = AF_INET6;
            address_length = sizeof(*address6);
        }
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return -1;

    if (LOBYTE(wsa_data.wVersion) != 2 || HIBYTE(wsa_data.wVersion) != 2) {
        WSACleanup();
        return -1;
    }

    sock = socket(address_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET) {
        WSACleanup();
        return -1;
    }

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                   (const char *)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                   (const char *)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR ||
        connect(sock, (const struct sockaddr *)&address, address_length) == SOCKET_ERROR ||
        sock > (SOCKET)INT_MAX) {
        closesocket(sock);
        WSACleanup();
        return -1;
    }

    return (int)sock;
}