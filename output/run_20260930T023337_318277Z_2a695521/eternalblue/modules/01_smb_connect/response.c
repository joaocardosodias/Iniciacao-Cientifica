#define _GNU_SOURCE

#ifdef _WIN32
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdio.h>
#else
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <netdb.h>
#include <unistd.h>
#include <stdio.h>
#endif

int smb_connect(const char *ip, int port)
{
    struct addrinfo hints;
    struct addrinfo *results = NULL;
    struct addrinfo *ai;
    char service[16];
    int gai_result;
#ifdef _WIN32
    WSADATA wsa_data;
    DWORD timeout_ms = 2000;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return -1;
#else
    struct timeval timeout;

    timeout.tv_sec = 2;
    timeout.tv_usec = 0;
#endif

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

    if (snprintf(service, sizeof(service), "%d", port) < 0)
        return -1;

    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;
    hints.ai_flags = 0;

    gai_result = getaddrinfo(ip, service, &hints, &results);
    if (gai_result != 0)
        return -1;

    for (ai = results; ai != NULL; ai = ai->ai_next) {
#ifdef _WIN32
        SOCKET sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

        if (sock == INVALID_SOCKET)
            continue;

        if (connect(sock, ai->ai_addr, (int)ai->ai_addrlen) == SOCKET_ERROR) {
            closesocket(sock);
            continue;
        }

        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                       (const char *)&timeout_ms, (int)sizeof(timeout_ms)) == SOCKET_ERROR ||
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                       (const char *)&timeout_ms, (int)sizeof(timeout_ms)) == SOCKET_ERROR) {
            closesocket(sock);
            continue;
        }

        freeaddrinfo(results);
        return (int)sock;
#else
        int sock = socket(ai->ai_family, ai->ai_socktype, ai->ai_protocol);

        if (sock < 0)
            continue;

        if (connect(sock, ai->ai_addr, ai->ai_addrlen) < 0) {
            close(sock);
            continue;
        }

        if (setsockopt(sock, SOL_SOCKET, SO_RCVTIMEO,
                       &timeout, sizeof(timeout)) < 0 ||
            setsockopt(sock, SOL_SOCKET, SO_SNDTIMEO,
                       &timeout, sizeof(timeout)) < 0) {
            close(sock);
            continue;
        }

        freeaddrinfo(results);
        return sock;
#endif
    }

    freeaddrinfo(results);
    return -1;
}