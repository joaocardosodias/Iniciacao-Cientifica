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
    struct sockaddr_storage address;
    int address_length;

    if (ip == NULL || port < 0 || port > 65535)
        return -1;

    state = InterlockedCompareExchange(&winsock_state, 1, 0);
    if (state == 0) {
        if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
            InterlockedExchange(&winsock_state, -1);
            return -1;
        }
        InterlockedExchange(&winsock_state, 2);
    } else {
        while (state == 1) {
            Sleep(0);
            state = InterlockedCompareExchange(&winsock_state, 0, 0);
        }
        if (state != 2)
            return -1;
    }

    ZeroMemory(&address, sizeof(address));
    if (InetPtonA(AF_INET, ip, &((struct sockaddr_in *)&address)->sin_addr) == 1) {
        struct sockaddr_in *addr4 = (struct sockaddr_in *)&address;
        addr4->sin_family = AF_INET;
        addr4->sin_port = htons((u_short)port);
        address_length = sizeof(*addr4);
    } else if (InetPtonA(AF_INET6, ip, &((struct sockaddr_in6 *)&address)->sin6_addr) == 1) {
        struct sockaddr_in6 *addr6 = (struct sockaddr_in6 *)&address;
        addr6->sin6_family = AF_INET6;
        addr6->sin6_port = htons((u_short)port);
        address_length = sizeof(*addr6);
    } else {
        return -1;
    }

    sock = socket(((struct sockaddr *)&address)->sa_family, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        return -1;

    if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR ||
        setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR ||
        connect(sock, (const struct sockaddr *)&address, address_length) == SOCKET_ERROR ||
        sock > (SOCKET)INT_MAX) {
        closesocket(sock);
        return -1;
    }

    return (int)sock;
}