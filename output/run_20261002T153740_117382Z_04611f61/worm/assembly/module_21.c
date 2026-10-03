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
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <stdio.h>

size_t scan_targets(const char *subnet, int port, char targets[][16], size_t max_hosts)
{
    const char *slash;
    char address_text[16];
    size_t address_length;
    unsigned int prefix = 0;
    struct in_addr parsed_address;
    uint32_t mask;
    uint32_t network;
    uint32_t broadcast;
    uint64_t first_address;
    uint64_t last_address;
    uint64_t current_address;
    size_t found = 0;
    WSADATA wsa_data;

    if (subnet == NULL || port < 1 || port > 65535)
        return 0;

    slash = strchr(subnet, '/');
    if (slash == NULL || strchr(slash + 1, '/') != NULL)
        return 0;

    address_length = (size_t)(slash - subnet);
    if (address_length == 0 || address_length >= sizeof(address_text))
        return 0;

    memcpy(address_text, subnet, address_length);
    address_text[address_length] = '\0';

    if (InetPtonA(AF_INET, address_text, &parsed_address) != 1)
        return 0;

    if (slash[1] == '\0')
        return 0;

    for (const char *p = slash + 1; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9')
            return 0;
        prefix = prefix * 10U + (unsigned int)(*p - '0');
        if (prefix > 32U)
            return 0;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return 0;

    if (prefix == 0)
        mask = 0;
    else
        mask = UINT32_MAX << (32U - prefix);

    network = ntohl(parsed_address.s_addr) & mask;
    broadcast = network | ~mask;

    if (prefix <= 30U) {
        first_address = (uint64_t)network + 1U;
        last_address = (uint64_t)broadcast - 1U;
    } else {
        first_address = network;
        last_address = broadcast;
    }

    for (current_address = first_address;
         current_address <= last_address;
         ++current_address) {
        SOCKET sock;
        struct sockaddr_in destination;
        u_long nonblocking = 1;
        int connect_result;
        int reachable = 0;

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
            continue;

        if (ioctlsocket(sock, FIONBIO, &nonblocking) != 0) {
            closesocket(sock);
            continue;
        }

        memset(&destination, 0, sizeof(destination));
        destination.sin_family = AF_INET;
        destination.sin_port = htons((u_short)port);
        destination.sin_addr.s_addr = htonl((uint32_t)current_address);

        connect_result = connect(sock, (struct sockaddr *)&destination, sizeof(destination));
        if (connect_result == 0) {
            reachable = 1;
        } else {
            int error = WSAGetLastError();

            if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS ||
                error == WSAEALREADY) {
                fd_set write_set;
                struct timeval timeout;
                int select_result;

                FD_ZERO(&write_set);
                FD_SET(sock, &write_set);
                timeout.tv_sec = 0;
                timeout.tv_usec = 250000;

                select_result = select(0, NULL, &write_set, NULL, &timeout);
                if (select_result > 0) {
                    int socket_error = 0;
                    int option_length = (int)sizeof(socket_error);

                    if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
                                   (char *)&socket_error, &option_length) == 0 &&
                        socket_error == 0)
                        reachable = 1;
                }
            }
        }

        closesocket(sock);

        if (reachable) {
            if (found < max_hosts) {
                uint32_t ip = (uint32_t)current_address;
                (void)snprintf(targets[found], 16, "%u.%u.%u.%u",
                               (unsigned int)((ip >> 24) & 0xFFU),
                               (unsigned int)((ip >> 16) & 0xFFU),
                               (unsigned int)((ip >> 8) & 0xFFU),
                               (unsigned int)(ip & 0xFFU));
            }
            ++found;
        }
    }

    WSACleanup();
    return found;
}