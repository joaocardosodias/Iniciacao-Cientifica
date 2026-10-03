#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

size_t scan_targets(const char *subnet, int port, char targets[][16], size_t max_hosts)
{
    char address_text[16];
    size_t address_length = 0;
    const char *slash;
    unsigned int prefix = 0;
    IN_ADDR parsed_address;
    uint32_t address_host;
    uint64_t host_mask;
    uint64_t network;
    uint64_t first_host;
    uint64_t last_host;
    uint64_t host;
    size_t reachable = 0;
    WSADATA wsa_data;

    if (subnet == NULL || port < 1 || port > 65535)
        return 0;

    slash = strchr(subnet, '/');
    if (slash == NULL)
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
        prefix = prefix * 10u + (unsigned int)(*p - '0');
        if (prefix > 32u)
            return 0;
    }

    address_host = ntohl(parsed_address.S_un.S_addr);
    host_mask = (UINT64_C(1) << (32u - prefix)) - 1u;
    network = (uint64_t)address_host & ~host_mask;
    first_host = network;
    last_host = network + host_mask;

    if (prefix <= 30u) {
        ++first_host;
        --last_host;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return 0;

    for (host = first_host; host <= last_host; ++host) {
        SOCKET sock;
        u_long nonblocking = 1;
        struct sockaddr_in destination;
        int connected = 0;

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
            continue;

        if (ioctlsocket(sock, FIONBIO, &nonblocking) == 0) {
            memset(&destination, 0, sizeof(destination));
            destination.sin_family = AF_INET;
            destination.sin_port = htons((u_short)port);
            destination.sin_addr.S_un.S_addr = htonl((uint32_t)host);

            if (connect(sock, (struct sockaddr *)&destination, sizeof(destination)) == 0) {
                connected = 1;
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
                    timeout.tv_usec = 200000;

                    select_result = select(0, NULL, &write_set, &error_set, &timeout);
                    if (select_result > 0 && FD_ISSET(sock, &write_set)) {
                        int socket_error = 0;
                        int error_length = sizeof(socket_error);

                        if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
                                       (char *)&socket_error, &error_length) == 0 &&
                            socket_error == 0)
                            connected = 1;
                    }
                }
            }
        }

        closesocket(sock);

        if (connected) {
            if (reachable < max_hosts && targets != NULL) {
                unsigned int value = (unsigned int)host;
                (void)snprintf(targets[reachable], 16, "%u.%u.%u.%u",
                               (value >> 24) & 0xffu,
                               (value >> 16) & 0xffu,
                               (value >> 8) & 0xffu,
                               value & 0xffu);
            }
            ++reachable;
        }
    }

    WSACleanup();
    return reachable;
}