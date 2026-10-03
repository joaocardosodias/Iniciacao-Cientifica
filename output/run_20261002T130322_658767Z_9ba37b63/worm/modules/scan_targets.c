#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

size_t scan_targets(const char *subnet, int port, char targets[][16], size_t max_hosts)
{
    const char *slash;
    char address_text[INET_ADDRSTRLEN];
    size_t address_length;
    unsigned int prefix = 0;
    struct in_addr parsed_address;
    uint32_t address_value;
    uint32_t mask;
    uint32_t network;
    uint32_t broadcast;
    uint64_t first_host;
    uint64_t last_host;
    uint64_t current;
    WSADATA wsa_data;
    size_t found = 0;

    if (subnet == NULL || port < 1 || port > 65535 ||
        (max_hosts != 0 && targets == NULL)) {
        return 0;
    }

    slash = strchr(subnet, '/');
    if (slash == NULL || strchr(slash + 1, '/') != NULL) {
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

    if (InetPtonA(AF_INET, address_text, &parsed_address) != 1) {
        return 0;
    }

    address_value = ntohl(parsed_address.s_addr);
    mask = prefix == 0 ? 0U : (UINT32_MAX << (32U - prefix));
    network = address_value & mask;
    broadcast = network | ~mask;

    if (prefix <= 30U) {
        first_host = (uint64_t)network + 1U;
        last_host = (uint64_t)broadcast - 1U;
    } else if (prefix == 31U) {
        first_host = network;
        last_host = broadcast;
    } else {
        first_host = network;
        last_host = network;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return 0;
    }

    for (current = first_host; current <= last_host; ++current) {
        SOCKET sock;
        struct sockaddr_in destination;
        u_long nonblocking = 1;
        int connect_result;
        int reachable = 0;

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            continue;
        }

        if (ioctlsocket(sock, FIONBIO, &nonblocking) == 0) {
            memset(&destination, 0, sizeof(destination));
            destination.sin_family = AF_INET;
            destination.sin_port = htons((u_short)port);
            destination.sin_addr.s_addr = htonl((uint32_t)current);

            connect_result = connect(sock, (struct sockaddr *)&destination,
                                     (int)sizeof(destination));
            if (connect_result == 0) {
                reachable = 1;
            } else {
                int connect_error = WSAGetLastError();

                if (connect_error == WSAEWOULDBLOCK ||
                    connect_error == WSAEINPROGRESS ||
                    connect_error == WSAEALREADY) {
                    fd_set write_set;
                    struct timeval timeout;
                    int select_result;

                    FD_ZERO(&write_set);
                    FD_SET(sock, &write_set);
                    timeout.tv_sec = 0;
                    timeout.tv_usec = 200000;

                    select_result = select(0, NULL, &write_set, NULL, &timeout);
                    if (select_result > 0 && FD_ISSET(sock, &write_set)) {
                        int socket_error = 0;
                        int error_length = (int)sizeof(socket_error);

                        if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
                                       (char *)&socket_error, &error_length) == 0 &&
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
                uint32_t host = (uint32_t)current;
                int written = snprintf(targets[found], 16, "%u.%u.%u.%u",
                                       (unsigned int)((host >> 24) & 0xffU),
                                       (unsigned int)((host >> 16) & 0xffU),
                                       (unsigned int)((host >> 8) & 0xffU),
                                       (unsigned int)(host & 0xffU));
                if (written < 0 || written >= 16) {
                    WSACleanup();
                    return found;
                }
            }
            ++found;
        }
    }

    WSACleanup();
    return found;
}