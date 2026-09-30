#define _GNU_SOURCE

#include <limits.h>
#include <stdio.h>
#include <stdlib.h>

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>

static INIT_ONCE smb_wsa_once = INIT_ONCE_STATIC_INIT;
static int smb_wsa_result;

static BOOL CALLBACK
smb_wsa_initialize(PINIT_ONCE once, PVOID parameter, PVOID *context)
{
    WSADATA data;

    (void)once;
    (void)parameter;
    (void)context;
    smb_wsa_result = WSAStartup(MAKEWORD(2, 2), &data);
    return TRUE;
}
#else
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <unistd.h>
#endif

int
smb_connect(const char *ip, int port)
{
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    char service[6];
    int result = -1;

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

#ifdef _WIN32
    if (!InitOnceExecuteOnce(&smb_wsa_once, smb_wsa_initialize, NULL, NULL) ||
        smb_wsa_result != 0)
        return -1;
#endif

    if (snprintf(service, sizeof(service), "%d", port) < 0)
        return -1;

    for (size_t i = 0; service[i] != '\0'; ++i) {
        if (i >= sizeof(service) - 1)
            return -1;
    }

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(ip, service, &hints, &addresses) != 0)
        return -1;

    for (address = addresses; address != NULL; address = address->ai_next) {
#ifdef _WIN32
        SOCKET socket_fd = socket(address->ai_family, address->ai_socktype,
                                  address->ai_protocol);
        DWORD timeout_ms = 2000;
        int option_length = (int)sizeof(timeout_ms);

        if (socket_fd == INVALID_SOCKET)
            continue;

        if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO,
                       (const char *)&timeout_ms, option_length) == SOCKET_ERROR ||
            setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO,
                       (const char *)&timeout_ms, option_length) == SOCKET_ERROR ||
            connect(socket_fd, address->ai_addr,
                    (int)address->ai_addrlen) == SOCKET_ERROR ||
            socket_fd > INT_MAX) {
            closesocket(socket_fd);
            continue;
        }

        result = (int)socket_fd;
#else
        int socket_fd = socket(address->ai_family, address->ai_socktype,
                               address->ai_protocol);
        struct timeval timeout = { .tv_sec = 2, .tv_usec = 0 };

        if (socket_fd < 0)
            continue;

        if (setsockopt(socket_fd, SOL_SOCKET, SO_RCVTIMEO,
                       &timeout, sizeof(timeout)) < 0 ||
            setsockopt(socket_fd, SOL_SOCKET, SO_SNDTIMEO,
                       &timeout, sizeof(timeout)) < 0 ||
            connect(socket_fd, address->ai_addr, address->ai_addrlen) < 0) {
            close(socket_fd);
            continue;
        }

        result = socket_fd;
#endif
        break;
    }

    freeaddrinfo(addresses);
    return result;
}