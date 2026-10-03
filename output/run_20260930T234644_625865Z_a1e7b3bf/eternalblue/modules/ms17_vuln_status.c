#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <limits.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

int ms17_vuln_status(const char *ip, int port)
{
    SOCKET sock;
    const unsigned char *packets[4];
    size_t packet_sizes[4];
    unsigned char *response = NULL;
    int result = -1;

    if (ip == NULL || port < 1 || port > 65535) {
        return -1;
    }

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    packets[0] = (const unsigned char *)SMB_NEGOTIATE_PKT;
    packet_sizes[0] = sizeof(SMB_NEGOTIATE_PKT);
    packets[1] = (const unsigned char *)SMB_SESSION_SETUP_PKT;
    packet_sizes[1] = sizeof(SMB_SESSION_SETUP_PKT);
    packets[2] = (const unsigned char *)SMB_TREE_CONNECT_PKT;
    packet_sizes[2] = sizeof(SMB_TREE_CONNECT_PKT);
    packets[3] = (const unsigned char *)SMB_TRANS_NAMED_PIPE_PKT;
    packet_sizes[3] = sizeof(SMB_TRANS_NAMED_PIPE_PKT);

    for (size_t i = 0; i < 4; ++i) {
        size_t sent = 0;

        while (sent < packet_sizes[i]) {
            size_t remaining = packet_sizes[i] - sent;
            int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
            int n = send(sock, (const char *)packets[i] + sent, chunk, 0);

            if (n == SOCKET_ERROR || n == 0) {
                goto cleanup;
            }
            sent += (size_t)n;
        }

        unsigned char header[4];
        size_t received = 0;

        while (received < sizeof(header)) {
            int n = recv(sock, (char *)header + received,
                         (int)(sizeof(header) - received), 0);
            if (n == SOCKET_ERROR || n == 0) {
                goto cleanup;
            }
            received += (size_t)n;
        }

        size_t body_length = ((size_t)header[1] << 16) |
                             ((size_t)header[2] << 8) |
                             (size_t)header[3];
        if (body_length > SIZE_MAX - sizeof(header)) {
            goto cleanup;
        }

        size_t response_length = sizeof(header) + body_length;
        unsigned char *new_response =
            (unsigned char *)realloc(response, response_length ? response_length : 1);
        if (new_response == NULL) {
            goto cleanup;
        }
        response = new_response;
        memcpy(response, header, sizeof(header));

        received = 0;
        while (received < body_length) {
            size_t remaining = body_length - received;
            int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
            int n = recv(sock, (char *)response + sizeof(header) + received,
                         chunk, 0);
            if (n == SOCKET_ERROR || n == 0) {
                goto cleanup;
            }
            received += (size_t)n;
        }

        if (i == 3) {
            size_t status_offset = (size_t)SMB_RESP_NT_STATUS_OFFSET;
            if (status_offset > response_length ||
                response_length - status_offset < sizeof(uint32_t)) {
                goto cleanup;
            }

            uint32_t status = (uint32_t)response[status_offset] |
                              ((uint32_t)response[status_offset + 1] << 8) |
                              ((uint32_t)response[status_offset + 2] << 16) |
                              ((uint32_t)response[status_offset + 3] << 24);
            result = status == (uint32_t)NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;
        }
    }

cleanup:
    free(response);
    closesocket(sock);
    return result;
}