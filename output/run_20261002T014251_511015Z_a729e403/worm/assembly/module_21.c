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
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <stdio.h>

size_t scan_targets(const char *subnet, int port, char targets[][16], size_t max_hosts)
{
    const char *slash;
    char address_text[16];
    size_t address_length;
    unsigned int prefix = 0;
    uint32_t address_network_order;
    uint32_t address_host_order;
    uint32_t mask;
    uint32_t network;
    uint64_t first;
    uint64_t last;
    uint64_t candidate;
    size_t stored = 0;
    size_t reachable = 0;
    WSADATA wsa_data;

    if (subnet == NULL || port < 1 || port > 65535 ||
        (max_hosts != 0 && targets == NULL)) {
        return 0;
    }

    slash = strchr(subnet, '/');
    if (slash == NULL) {
        return 0;
    }

    address_length = (size_t)(slash - subnet);
    if (address_length == 0 || address_length >= sizeof(address_text)) {
        return 0;
    }

    memcpy(address_text, subnet, address_length);
    address_text[address_length] = '\0';

    if (slash[1] == '\0') {
        return 0;
    }
    for (const char *p = slash + 1; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9') {
            return 0;
        }
        prefix = prefix * 10U + (unsigned int)(*p - '0');
        if (prefix > 32U) {
            return 0;
        }
    }

    if (InetPtonA(AF_INET, address_text, &address_network_order) != 1) {
        return 0;
    }

    address_host_order = ntohl(address_network_order);
    mask = prefix == 0U ? 0U : (uint32_t)(0xFFFFFFFFUL << (32U - prefix));
    network = address_host_order & mask;
    first = (uint64_t)network;
    last = (uint64_t)network | (uint64_t)(uint32_t)~mask;

    if (prefix <= 30U) {
        ++first;
        --last;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return 0;
    }

    for (candidate = first; candidate <= last; ++candidate) {
        SOCKET sock;
        struct sockaddr_in destination;
        u_long nonblocking = 1;
        int connect_result;
        int connected = 0;

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            continue;
        }

        if (ioctlsocket(sock, FIONBIO, &nonblocking) != 0) {
            closesocket(sock);
            continue;
        }

        memset(&destination, 0, sizeof(destination));
        destination.sin_family = AF_INET;
        destination.sin_port = htons((u_short)port);
        destination.sin_addr.s_addr = htonl((uint32_t)candidate);

        connect_result = connect(sock, (const struct sockaddr *)&destination,
                                 (int)sizeof(destination));
        if (connect_result == 0) {
            connected = 1;
        } else {
            int error = WSAGetLastError();
            if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS ||
                error == WSAEALREADY) {
                fd_set write_set;
                fd_set except_set;
                struct timeval timeout;
                int select_result;

                FD_ZERO(&write_set);
                FD_ZERO(&except_set);
                FD_SET(sock, &write_set);
                FD_SET(sock, &except_set);
                timeout.tv_sec = 0;
                timeout.tv_usec = 200000;

                select_result = select(0, NULL, &write_set, &except_set, &timeout);
                if (select_result > 0) {
                    int socket_error = 0;
                    int option_length = (int)sizeof(socket_error);
                    if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
                                   (char *)&socket_error, &option_length) == 0 &&
                        socket_error == 0) {
                        connected = 1;
                    }
                }
            }
        }

        if (connected) {
            ++reachable;
            if (stored < max_hosts) {
                uint32_t host = (uint32_t)candidate;
                snprintf(targets[stored], 16, "%u.%u.%u.%u",
                         (unsigned int)((host >> 24) & 0xFFU),
                         (unsigned int)((host >> 16) & 0xFFU),
                         (unsigned int)((host >> 8) & 0xFFU),
                         (unsigned int)(host & 0xFFU));
                ++stored;
            }
        }

        closesocket(sock);
    }

    WSACleanup();
    return reachable;
}