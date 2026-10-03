#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

size_t scan_targets(const char *subnet, int port, char targets[][16], size_t max_hosts)
{
    const char *slash;
    size_t address_length;
    char address_text[INET_ADDRSTRLEN];
    unsigned int prefix = 0;
    struct in_addr parsed_address;
    uint32_t address_host_order;
    uint32_t mask;
    uint32_t network;
    uint32_t broadcast;
    uint64_t first_address;
    uint64_t last_address;
    WSADATA wsa_data;
    size_t found = 0;

    if (subnet == NULL || targets == NULL || max_hosts == 0 ||
        port < 1 || port > 65535) {
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
        prefix = prefix * 10u + (unsigned int)(*p - '0');
        if (prefix > 32u) {
            return 0;
        }
    }

    if (InetPtonA(AF_INET, address_text, &parsed_address) != 1) {
        return 0;
    }

    address_host_order = ntohl(parsed_address.s_addr);
    mask = prefix == 0 ? 0u : (UINT32_MAX << (32u - prefix));
    network = address_host_order & mask;
    broadcast = network | ~mask;

    if (prefix <= 30u) {
        first_address = (uint64_t)network + 1u;
        last_address = (uint64_t)broadcast - 1u;
    } else {
        first_address = network;
        last_address = broadcast;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return 0;
    }

    for (uint64_t host = first_address;
         host <= last_address && found < max_hosts;
         ++host) {
        SOCKET sock;
        struct sockaddr_in destination;
        u_long nonblocking = 1;
        int connect_result;
        int connected = 0;

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            continue;
        }

        if (ioctlsocket(sock, FIONBIO, &nonblocking) == 0) {
            memset(&destination, 0, sizeof(destination));
            destination.sin_family = AF_INET;
            destination.sin_port = htons((u_short)port);
            destination.sin_addr.s_addr = htonl((uint32_t)host);

            connect_result = connect(sock, (struct sockaddr *)&destination,
                                     (int)sizeof(destination));
            if (connect_result == 0) {
                connected = 1;
            } else {
                int connect_error = WSAGetLastError();
                if (connect_error == WSAEWOULDBLOCK ||
                    connect_error == WSAEINPROGRESS ||
                    connect_error == WSAEALREADY) {
                    fd_set write_set;
                    fd_set except_set;
                    struct timeval timeout;

                    FD_ZERO(&write_set);
                    FD_ZERO(&except_set);
                    FD_SET(sock, &write_set);
                    FD_SET(sock, &except_set);
                    timeout.tv_sec = 0;
                    timeout.tv_usec = 250000;

                    if (select(0, NULL, &write_set, &except_set, &timeout) > 0) {
                        int socket_error = 0;
                        int socket_error_length = (int)sizeof(socket_error);

                        if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
                                       (char *)&socket_error,
                                       &socket_error_length) == 0 &&
                            socket_error == 0) {
                            connected = 1;
                        }
                    }
                }
            }
        }

        closesocket(sock);

        if (connected) {
            uint32_t network_address = htonl((uint32_t)host);
            const unsigned char *octets =
                (const unsigned char *)&network_address;

            snprintf(targets[found], 16, "%u.%u.%u.%u",
                     (unsigned int)octets[0],
                     (unsigned int)octets[1],
                     (unsigned int)octets[2],
                     (unsigned int)octets[3]);
            ++found;
        }
    }

    WSACleanup();
    return found;
}