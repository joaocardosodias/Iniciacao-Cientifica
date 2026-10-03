#include "config.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>

int smb_connect(const char *ip, int port)
{
    struct addrinfo hints;
    struct addrinfo *result = NULL;
    struct addrinfo *entry;
    char service[16];
    WSADATA wsa_data;
    SOCKET fd = INVALID_SOCKET;
    DWORD timeout_ms = 5000;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return -1;

    if (ip == NULL || port < 0 || port > 65535)
        return -1;

    if (snprintf(service, sizeof(service), "%d", port) < 0)
        return -1;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    if (getaddrinfo(ip, service, &hints, &result) != 0)
        return -1;

    for (entry = result; entry != NULL; entry = entry->ai_next) {
        fd = socket(entry->ai_family, entry->ai_socktype, entry->ai_protocol);
        if (fd == INVALID_SOCKET)
            continue;
        if (connect(fd, entry->ai_addr, (int)entry->ai_addrlen) == SOCKET_ERROR) {
            closesocket(fd);
            fd = INVALID_SOCKET;
            continue;
        }
        if (setsockopt(fd, SOL_SOCKET, SO_RCVTIMEO, (const char *)&timeout_ms,
                       (int)sizeof(timeout_ms)) == SOCKET_ERROR ||
            setsockopt(fd, SOL_SOCKET, SO_SNDTIMEO, (const char *)&timeout_ms,
                       (int)sizeof(timeout_ms)) == SOCKET_ERROR) {
            closesocket(fd);
            fd = INVALID_SOCKET;
            continue;
        }
        break;
    }

    freeaddrinfo(result);
    return fd == INVALID_SOCKET ? -1 : (int)fd;
}
