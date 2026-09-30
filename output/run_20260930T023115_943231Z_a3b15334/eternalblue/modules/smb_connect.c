#define _GNU_SOURCE
#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <unistd.h>
#include <errno.h>
#endif
#include <limits.h>
#include <stdio.h>

#ifdef _WIN32
static INIT_ONCE smb_winsock_once = INIT_ONCE_STATIC_INIT;
static int smb_winsock_status;

static BOOL CALLBACK smb_winsock_initialize(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
    WSADATA data;
    (void)once;
    (void)parameter;
    (void)context;
    smb_winsock_status = WSAStartup(MAKEWORD(2, 2), &data);
    return TRUE;
}
#endif

int smb_connect(const char *ip, int port)
{
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    char service[16];
    int result = -1;

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

#ifdef _WIN32
    if (!InitOnceExecuteOnce(&smb_winsock_once, smb_winsock_initialize, NULL, NULL) ||
        smb_winsock_status != 0)
        return -1;
#endif

    if (snprintf(service, sizeof(service), "%d", port) < 0)
        return -1;

    hints = (struct addrinfo){0};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = AI_NUMERICHOST;

    if (getaddrinfo(ip, service, &hints, &addresses) != 0)
        return -1;

    for (address = addresses; address != NULL; address = address->ai_next) {
#ifdef _WIN32
        SOCKET socket_fd = socket(address->ai_family, address->ai_socktype,
                                  address->ai_protocol);
        DWORD timeout_ms = 2000;

        if (socket_fd == INVALID_SOCKET)
            continue;

        if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO,
                       (const char *)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR ||
            setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO,
                       (const char *)&timeout_ms, sizeof(timeout_ms)) == SOCKET_ERROR ||
            connect(socket_fd, address->ai_addr, (int)address->ai_addrlen) == SOCKET_ERROR) {
            closesocket(socket_fd);
            continue;
        }

        if (socket_fd > (SOCKET)INT_MAX) {
            closesocket(socket_fd);
            continue;
        }
        result = (int)socket_fd;
        break;
#else
        int socket_fd = socket(address->ai_family, address->ai_socktype,
                               address->ai_protocol);
        struct timeval timeout = {2, 0};

        if (socket_fd < 0)
            continue;

        if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO,
                       &timeout, sizeof(timeout)) < 0 ||
            setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO,
                       &timeout, sizeof(timeout)) < 0 ||
            connect(socket_fd, address->ai_addr,
                    (socklen_t)address->ai_addrlen) < 0) {
            close(socket_fd);
            continue;
        }

        result = socket_fd;
        break;
#endif
    }

    freeaddrinfo(addresses);
    return result;
}