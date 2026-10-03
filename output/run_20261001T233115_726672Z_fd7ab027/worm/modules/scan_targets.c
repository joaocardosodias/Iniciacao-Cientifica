#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdio.h>
#include <string.h>

size_t scan_targets(const char *subnet, int port, char targets[][16], size_t max_hosts)
{
    WSADATA wsa_data;
    const char *slash;
    char address_text[INET_ADDRSTRLEN];
    size_t address_length;
    unsigned int prefix = 0;
    struct in_addr address;
    uint32_t mask;
    uint32_t network;
    uint64_t first;
    uint64_t last;
    uint64_t candidate;
    size_t found = 0;

    if (subnet == NULL || targets == NULL || max_hosts == 0 ||
        port < 1 || port > 65535) {
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

    if (InetPtonA(AF_INET, address_text, &address) != 1) {
        return 0;
    }

    if (prefix == 0U) {
        mask = 0;
    } else {
        mask = UINT32_MAX << (32U - prefix);
    }

    network = ntohl(address.s_addr) & mask;
    first = network;
    last = (uint64_t)(network | ~mask);

    if (prefix <= 30U) {
        ++first;
        --last;
    }

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0) {
        return 0;
    }

    for (candidate = first; candidate <= last && found < max_hosts; ++candidate) {
        SOCKET sock;
        u_long nonblocking = 1;
        struct sockaddr_in endpoint;
        int connect_result;
        int reachable = 0;

        sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        if (sock == INVALID_SOCKET) {
            continue;
        }

        if (ioctlsocket(sock, FIONBIO, &nonblocking) != 0) {
            closesocket(sock);
            continue;
        }

        memset(&endpoint, 0, sizeof(endpoint));
        endpoint.sin_family = AF_INET;
        endpoint.sin_port = htons((u_short)port);
        endpoint.sin_addr.s_addr = htonl((uint32_t)candidate);

        connect_result = connect(sock, (struct sockaddr *)&endpoint, sizeof(endpoint));
        if (connect_result == 0) {
            reachable = 1;
        } else {
            int error = WSAGetLastError();
            if (error == WSAEWOULDBLOCK || error == WSAEINPROGRESS ||
                error == WSAEALREADY) {
                fd_set write_set;
                fd_set except_set;
                struct timeval timeout;
                int selected;

                FD_ZERO(&write_set);
                FD_ZERO(&except_set);
                FD_SET(sock, &write_set);
                FD_SET(sock, &except_set);
                timeout.tv_sec = 0;
                timeout.tv_usec = 200000;

                selected = select(0, NULL, &write_set, &except_set, &timeout);
                if (selected > 0) {
                    int socket_error = 0;
                    int option_length = (int)sizeof(socket_error);
                    if (getsockopt(sock, SOL_SOCKET, SO_ERROR,
                                   (char *)&socket_error, &option_length) == 0 &&
                        socket_error == 0) {
                        reachable = 1;
                    }
                }
            } else if (error == WSAEISCONN) {
                reachable = 1;
            }
        }

        closesocket(sock);

        if (reachable) {
            uint32_t host = (uint32_t)candidate;
            int length = snprintf(targets[found], 16, "%u.%u.%u.%u",
                                  (unsigned int)((host >> 24) & 0xffU),
                                  (unsigned int)((host >> 16) & 0xffU),
                                  (unsigned int)((host >> 8) & 0xffU),
                                  (unsigned int)(host & 0xffU));
            if (length > 0 && length < 16) {
                ++found;
            }
        }
    }

    WSACleanup();
    return found;
}