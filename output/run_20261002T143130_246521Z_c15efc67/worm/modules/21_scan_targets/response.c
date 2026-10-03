#include <winsock2.h>
#include <ws2tcpip.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

size_t scan_targets(const char *subnet, int port, char targets[][16], size_t max_hosts)
{
    WSADATA wsa_data;
    struct in_addr address;
    char address_text[16];
    const char *slash;
    const char *p;
    unsigned int prefix = 0;
    uint32_t host_address;
    uint32_t mask;
    uint32_t network;
    uint32_t broadcast;
    uint64_t first;
    uint64_t end;
    uint64_t current;
    size_t found = 0;
    size_t stored = 0;

    if (subnet == NULL || port < 1 || port > 65535 ||
        (max_hosts != 0 && targets == NULL))
        return 0;

    slash = strchr(subnet, '/');
    if (slash == NULL || slash == subnet || (size_t)(slash - subnet) >= sizeof(address_text))
        return 0;

    memcpy(address_text, subnet, (size_t)(slash - subnet));
    address_text[slash - subnet] = '\0';

    if (strchr(slash + 1, '/') != NULL || slash[1] == '\0')
        return 0;

    for (p = slash + 1; *p != '\0'; ++p) {
        if (*p < '0' || *p > '9')
            return 0;
        prefix = prefix * 10U + (unsigned int)(*p - '0');
        if (prefix > 32U)
            return 0;
    }

    if (InetPtonA(AF_INET, address_text, &address) != 1)
        return 0;

    host_address = ntohl(address.s_addr);
    mask = prefix == 0U ? 0U : (uint32_t)(UINT32_MAX << (32U - prefix));
    network = host_address & mask;
    broadcast = network | ~mask;

    if (prefix <= 30U) {
        first = (uint64_t)network + 1U;
        end = (uint64_t)broadcast;
    } else {
        first = (uint64_t)network;
        end = (uint64_t)broadcast + 1U;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return 0;

    for (current = first; current < end; ++current) {
        SOCKET sock;
        u_long nonblocking = 1;
        struct sockaddr_in peer;
        int connect_result;
        int reachable = 0;

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET)
            continue;

        if (ioctlsocket(sock, FIONBIO, &nonblocking) == SOCKET_ERROR) {
            closesocket(sock);
            continue;
        }

        memset(&peer, 0, sizeof(peer));
        peer.sin_family = AF_INET;
        peer.sin_port = htons((u_short)port);
        peer.sin_addr.s_addr = htonl((uint32_t)current);

        connect_result = connect(sock, (const struct sockaddr *)&peer, sizeof(peer));
        if (connect_result == 0) {
            reachable = 1;
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
                timeout.tv_usec = 250000;

                select_result = select(0, NULL, &write_set, &except_set, &timeout);
                if (select_result > 0 &&
                    (FD_ISSET(sock, &write_set) || FD_ISSET(sock, &except_set))) {
                    int socket_error = 0;
                    int socket_error_length = (int)sizeof(socket_error);

                    if (getsockopt(sock, SOL_SOCKET, SO_ERROR, (char *)&socket_error,
                                   &socket_error_length) == 0 &&
                        socket_error == 0)
                        reachable = 1;
                }
            }
        }

        closesocket(sock);

        if (reachable) {
            ++found;
            if (stored < max_hosts) {
                unsigned int a = (unsigned int)((uint32_t)current >> 24);
                unsigned int b = (unsigned int)(((uint32_t)current >> 16) & 0xffU);
                unsigned int c = (unsigned int)(((uint32_t)current >> 8) & 0xffU);
                unsigned int d = (unsigned int)((uint32_t)current & 0xffU);

                if (snprintf(targets[stored], 16, "%u.%u.%u.%u", a, b, c, d) >= 0)
                    ++stored;
            }
        }
    }

    WSACleanup();
    return found;
}