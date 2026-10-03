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
#include <stdio.h>
#include <string.h>

size_t scan_targets(const char *subnet, int port, char targets[][16], size_t max_hosts)
{
    WSADATA wsa_data;
    char address_text[16];
    size_t address_length = 0;
    const char *slash;
    unsigned int prefix = 0;
    struct in_addr parsed_address;
    uint32_t address, mask, network, broadcast;
    uint64_t first_host, last_host, candidate;
    size_t found = 0;

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
        prefix = prefix * 10u + (unsigned int)(*p - '0');
        if (prefix > 32u) {
            return 0;
        }
    }

    if (InetPtonA(AF_INET, address_text, &parsed_address) != 1) {
        return 0;
    }

    address = ntohl(parsed_address.s_addr);
    mask = prefix == 0 ? 0u : (uint32_t)(0xffffffffu << (32u - prefix));
    network = address & mask;
    broadcast = network | ~mask;

    if (prefix <= 30u) {
        first_host = (uint64_t)network + 1u;
        last_host = (uint64_t)broadcast - 1u;
    } else {
        first_host = network;
        last_host = broadcast;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return 0;
    }

    if (first_host <= last_host) {
        for (candidate = first_host; candidate <= last_host; ++candidate) {
            SOCKET sock;
            u_long nonblocking = 1;
            struct sockaddr_in destination;
            int connected = 0;

            sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
            if (sock == INVALID_SOCKET) {
                continue;
            }

            memset(&destination, 0, sizeof(destination));
            destination.sin_family = AF_INET;
            destination.sin_port = htons((u_short)port);
            destination.sin_addr.s_addr = htonl((uint32_t)candidate);

            if (ioctlsocket(sock, FIONBIO, &nonblocking) == 0) {
                int result = connect(sock, (struct sockaddr *)&destination,
                                     (int)sizeof(destination));

                if (result == 0) {
                    connected = 1;
                } else {
                    int connect_error = WSAGetLastError();

                    if (connect_error == WSAEWOULDBLOCK ||
                        connect_error == WSAEINPROGRESS ||
                        connect_error == WSAEALREADY) {
                        fd_set write_set;
                        fd_set except_set;
                        struct timeval timeout;
                        int select_result;

                        FD_ZERO(&write_set);
                        FD_ZERO(&except_set);
                        FD_SET(sock, &write_set);
                        FD_SET(sock, &except_set);
                        timeout.tv_sec = 0;
                        timeout.tv_usec = 250000;

                        select_result = select(0, NULL, &write_set, &except_set,
                                               &timeout);
                        if (select_result > 0) {
                            int socket_error = 0;
                            int error_length = (int)sizeof(socket_error);

                            if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
                                           (char *)&socket_error,
                                           &error_length) == 0 &&
                                socket_error == 0) {
                                connected = 1;
                            }
                        }
                    } else if (connect_error == WSAEISCONN) {
                        connected = 1;
                    }
                }
            }

            closesocket(sock);

            if (connected) {
                if (found < max_hosts) {
                    unsigned int octet1 = (unsigned int)((candidate >> 24) & 0xffu);
                    unsigned int octet2 = (unsigned int)((candidate >> 16) & 0xffu);
                    unsigned int octet3 = (unsigned int)((candidate >> 8) & 0xffu);
                    unsigned int octet4 = (unsigned int)(candidate & 0xffu);

                    sprintf(targets[found], "%u.%u.%u.%u",
                            octet1, octet2, octet3, octet4);
                }
                ++found;
            }
        }
    }

    WSACleanup();
    return found;
}