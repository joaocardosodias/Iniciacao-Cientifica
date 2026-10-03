#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

size_t scan_targets(const char *subnet, int port, char targets[][16], size_t max_hosts)
{
    WSADATA wsa_data;
    const char *slash;
    char address_text[16];
    size_t address_length;
    unsigned int prefix = 0;
    const char *p;
    struct in_addr parsed_address;
    uint32_t address_host;
    uint32_t host_mask;
    uint32_t network;
    uint32_t broadcast;
    uint64_t first_host;
    uint64_t last_host;
    uint64_t candidate;
    size_t found = 0;

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

    p = slash + 1;
    if (*p == '\0')
        return 0;
    for (; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9')
            return 0;
        prefix = prefix * 10u + (unsigned int)(*p - '0');
        if (prefix > 32u)
            return 0;
    }

    if (InetPtonA(AF_INET, address_text, &parsed_address) != 1)
        return 0;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return 0;

    address_host = ntohl(parsed_address.s_addr);
    host_mask = prefix == 0u
        ? UINT32_MAX
        : (uint32_t)((UINT64_C(1) << (32u - prefix)) - 1u);
    network = address_host & ~host_mask;
    broadcast = network | host_mask;

    if (prefix <= 30u) {
        first_host = (uint64_t)network + 1u;
        last_host = (uint64_t)broadcast - 1u;
    } else {
        first_host = network;
        last_host = broadcast;
    }

    for (candidate = first_host; candidate <= last_host; ++candidate) {
        SOCKET sock;
        struct sockaddr_in destination;
        int connect_result;
        int reachable = 0;
        u_long nonblocking = 1;

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
            continue;

        if (ioctlsocket(sock, FIONBIO, &nonblocking) == 0) {
            memset(&destination, 0, sizeof(destination));
            destination.sin_family = AF_INET;
            destination.sin_port = htons((u_short)port);
            destination.sin_addr.s_addr = htonl((uint32_t)candidate);

            connect_result = connect(sock, (struct sockaddr *)&destination,
                                     sizeof(destination));
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
                        int socket_error_length = sizeof(socket_error);

                        if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
                                       (char *)&socket_error,
                                       &socket_error_length) == 0 &&
                            socket_error == 0)
                            reachable = 1;
                    }
                }
            }
        }

        closesocket(sock);

        if (reachable) {
            if (found < max_hosts && targets != NULL) {
                uint32_t host = (uint32_t)candidate;
                snprintf(targets[found], 16, "%u.%u.%u.%u",
                         (unsigned int)((host >> 24) & 0xffu),
                         (unsigned int)((host >> 16) & 0xffu),
                         (unsigned int)((host >> 8) & 0xffu),
                         (unsigned int)(host & 0xffu));
            }
            ++found;
        }
    }

    WSACleanup();
    return found;
}