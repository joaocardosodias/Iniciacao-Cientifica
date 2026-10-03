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
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

size_t scan_targets(const char *subnet, int port, char targets[][16], size_t max_hosts)
{
    WSADATA wsa_data;
    char input[64];
    char *slash;
    size_t input_length;
    unsigned long prefix = 0;
    size_t i;
    struct in_addr parsed_address;
    uint32_t address;
    uint32_t mask;
    uint32_t network;
    uint32_t broadcast;
    uint64_t first_host;
    uint64_t last_host;
    uint64_t host;
    size_t found = 0;

    if (subnet == NULL || port < 1 || port > 65535 ||
        (max_hosts != 0 && targets == NULL)) {
        return (size_t)-1;
    }

    input_length = strlen(subnet);
    if (input_length == 0 || input_length >= sizeof(input)) {
        return (size_t)-1;
    }

    memcpy(input, subnet, input_length + 1);
    slash = strchr(input, '/');
    if (slash == NULL || slash == input || slash[1] == '\0' ||
        strchr(slash + 1, '/') != NULL) {
        return (size_t)-1;
    }

    *slash++ = '\0';
    for (i = 0; slash[i] != '\0'; ++i) {
        if (slash[i] < '0' || slash[i] > '9') {
            return (size_t)-1;
        }
        prefix = prefix * 10 + (unsigned long)(slash[i] - '0');
        if (prefix > 32) {
            return (size_t)-1;
        }
    }

    if (InetPtonA(AF_INET, input, &parsed_address) != 1) {
        return (size_t)-1;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return (size_t)-1;
    }

    address = ntohl(parsed_address.s_addr);
    mask = prefix == 0 ? 0U : (uint32_t)(UINT32_MAX << (32 - prefix));
    network = address & mask;
    broadcast = network | ~mask;

    if (prefix <= 30) {
        first_host = (uint64_t)network + 1;
        last_host = (uint64_t)broadcast - 1;
    } else {
        first_host = network;
        last_host = broadcast;
    }

    for (host = first_host; host <= last_host; ++host) {
        SOCKET sock;
        struct sockaddr_in endpoint;
        u_long nonblocking = 1;
        int connect_result;
        int reachable = 0;

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            continue;
        }

        if (ioctlsocket(sock, FIONBIO, &nonblocking) == 0) {
            memset(&endpoint, 0, sizeof(endpoint));
            endpoint.sin_family = AF_INET;
            endpoint.sin_port = htons((u_short)port);
            endpoint.sin_addr.s_addr = htonl((uint32_t)host);

            connect_result = connect(sock, (struct sockaddr *)&endpoint, sizeof(endpoint));
            if (connect_result == 0) {
                reachable = 1;
            } else {
                int connect_error = WSAGetLastError();
                if (connect_error == WSAEWOULDBLOCK ||
                    connect_error == WSAEINPROGRESS ||
                    connect_error == WSAEALREADY) {
                    fd_set write_set;
                    fd_set error_set;
                    struct timeval timeout;
                    int select_result;

                    FD_ZERO(&write_set);
                    FD_ZERO(&error_set);
                    FD_SET(sock, &write_set);
                    FD_SET(sock, &error_set);
                    timeout.tv_sec = 0;
                    timeout.tv_usec = 250000;

                    select_result = select(0, NULL, &write_set, &error_set, &timeout);
                    if (select_result > 0 &&
                        (FD_ISSET(sock, &write_set) || FD_ISSET(sock, &error_set))) {
                        int socket_error = 0;
                        int socket_error_length = (int)sizeof(socket_error);
                        if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
                                       (char *)&socket_error,
                                       &socket_error_length) == 0 &&
                            socket_error == 0) {
                            reachable = 1;
                        }
                    }
                }
            }
        }

        closesocket(sock);

        if (reachable) {
            if (found < max_hosts) {
                (void)snprintf(targets[found], 16, "%u.%u.%u.%u",
                               (unsigned)((uint32_t)host >> 24),
                               (unsigned)(((uint32_t)host >> 16) & 0xffU),
                               (unsigned)(((uint32_t)host >> 8) & 0xffU),
                               (unsigned)((uint32_t)host & 0xffU));
            }
            ++found;
        }
    }

    WSACleanup();
    return found;
}