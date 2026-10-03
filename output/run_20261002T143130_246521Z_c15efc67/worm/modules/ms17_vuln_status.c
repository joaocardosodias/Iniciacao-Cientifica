#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

int ms17_vuln_status(const char *ip, int port)
{
    uint8_t negotiate_pkt[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup_pkt[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect_pkt[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t trans_named_pipe_pkt[sizeof(SMB_TRANS_NAMED_PIPE_PKT)];
    uint8_t *packets[4];
    size_t packet_lengths[4];
    SOCKET sock;
    uint8_t *response = NULL;
    size_t response_size = 0;
    int result = -1;

    if (ip == NULL)
        return -1;

    memcpy(negotiate_pkt, SMB_NEGOTIATE_PKT, sizeof(negotiate_pkt));
    memcpy(session_setup_pkt, SMB_SESSION_SETUP_PKT, sizeof(session_setup_pkt));
    memcpy(tree_connect_pkt, SMB_TREE_CONNECT_PKT, sizeof(tree_connect_pkt));
    memcpy(trans_named_pipe_pkt, SMB_TRANS_NAMED_PIPE_PKT, sizeof(trans_named_pipe_pkt));

    packets[0] = negotiate_pkt;
    packets[1] = session_setup_pkt;
    packets[2] = tree_connect_pkt;
    packets[3] = trans_named_pipe_pkt;

    packet_lengths[0] = sizeof(SMB_NEGOTIATE_PKT) - 1;
    packet_lengths[1] = sizeof(SMB_SESSION_SETUP_PKT) - 1;
    packet_lengths[2] = sizeof(SMB_TREE_CONNECT_PKT) - 1;
    packet_lengths[3] = sizeof(SMB_TRANS_NAMED_PIPE_PKT) - 1;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return -1;

    for (size_t i = 0; i < 4; ++i) {
        size_t sent = 0;

        while (sent < packet_lengths[i]) {
            int n = send(sock, (const char *)packets[i] + sent,
                         (int)(packet_lengths[i] - sent), 0);
            if (n == SOCKET_ERROR || n == 0)
                goto cleanup;
            sent += (size_t)n;
        }

        {
            uint8_t netbios_header[4];
            size_t received = 0;
            uint32_t payload_length;

            while (received < sizeof(netbios_header)) {
                int n = recv(sock, (char *)netbios_header + received,
                             (int)(sizeof(netbios_header) - received), 0);
                if (n == SOCKET_ERROR || n == 0)
                    goto cleanup;
                received += (size_t)n;
            }

            payload_length = ((uint32_t)netbios_header[1] << 16) |
                             ((uint32_t)netbios_header[2] << 8) |
                             (uint32_t)netbios_header[3];
            response_size = (size_t)payload_length + sizeof(netbios_header);
            response = (uint8_t *)malloc(response_size);
            if (response == NULL)
                goto cleanup;

            memcpy(response, netbios_header, sizeof(netbios_header));
            received = sizeof(netbios_header);

            while (received < response_size) {
                size_t remaining = response_size - received;
                int request = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
                int n = recv(sock, (char *)response + received, request, 0);
                if (n == SOCKET_ERROR || n == 0)
                    goto cleanup;
                received += (size_t)n;
            }
        }

        if (i == 1) {
            if (response_size < 34)
                goto cleanup;
            tree_connect_pkt[32] = response[32];
            tree_connect_pkt[33] = response[33];
        } else if (i == 2) {
            if (response_size < 34)
                goto cleanup;
            trans_named_pipe_pkt[28] = response[28];
            trans_named_pipe_pkt[29] = response[29];
            trans_named_pipe_pkt[32] = response[32];
            trans_named_pipe_pkt[33] = response[33];
        } else if (i == 3) {
            size_t status_offset = (size_t)SMB_RESP_NT_STATUS_OFFSET;
            uint32_t status;

            if (status_offset > response_size ||
                response_size - status_offset < sizeof(status))
                goto cleanup;

            status = (uint32_t)response[status_offset] |
                     ((uint32_t)response[status_offset + 1] << 8) |
                     ((uint32_t)response[status_offset + 2] << 16) |
                     ((uint32_t)response[status_offset + 3] << 24);
            result = status == (uint32_t)NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;
        }

        free(response);
        response = NULL;
        response_size = 0;
    }

cleanup:
    free(response);
    closesocket(sock);
    return result;
}