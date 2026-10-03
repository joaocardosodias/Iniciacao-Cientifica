#include <winsock2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

int ms17_vuln_status(const char *ip, int port)
{
    uint8_t negotiate[sizeof(SMB_NEGOTIATE_PKT) - 1];
    uint8_t session_setup[sizeof(SMB_SESSION_SETUP_PKT) - 1];
    uint8_t tree_connect[sizeof(SMB_TREE_CONNECT_PKT) - 1];
    uint8_t trans_named_pipe[sizeof(SMB_TRANS_NAMED_PIPE_PKT) - 1];
    uint8_t *packets[4];
    size_t packet_lengths[4];
    uint8_t *response = NULL;
    SOCKET sock;
    int result = -1;
    uint16_t user_id = 0;
    uint16_t tree_id = 0;
    size_t i;

    if (ip == NULL)
        return -1;

    memcpy(negotiate, SMB_NEGOTIATE_PKT, sizeof(negotiate));
    memcpy(session_setup, SMB_SESSION_SETUP_PKT, sizeof(session_setup));
    memcpy(tree_connect, SMB_TREE_CONNECT_PKT, sizeof(tree_connect));
    memcpy(trans_named_pipe, SMB_TRANS_NAMED_PIPE_PKT, sizeof(trans_named_pipe));

    packets[0] = negotiate;
    packets[1] = session_setup;
    packets[2] = tree_connect;
    packets[3] = trans_named_pipe;

    packet_lengths[0] = sizeof(SMB_NEGOTIATE_PKT) - 1;
    packet_lengths[1] = sizeof(SMB_SESSION_SETUP_PKT) - 1;
    packet_lengths[2] = sizeof(SMB_TREE_CONNECT_PKT) - 1;
    packet_lengths[3] = sizeof(SMB_TRANS_NAMED_PIPE_PKT) - 1;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return -1;

    response = (uint8_t *)malloc(131075u);
    if (response == NULL)
        goto cleanup;

    for (i = 0; i < 4; ++i) {
        size_t sent = 0;
        size_t response_length;
        uint32_t netbios_length;

        while (sent < packet_lengths[i]) {
            int n = send(sock, (const char *)packets[i] + sent,
                         (int)(packet_lengths[i] - sent), 0);
            if (n == SOCKET_ERROR || n == 0)
                goto cleanup;
            sent += (size_t)n;
        }

        for (;;) {
            size_t received = 0;

            while (received < 4) {
                int n = recv(sock, (char *)response + received,
                             (int)(4 - received), 0);
                if (n == SOCKET_ERROR || n == 0)
                    goto cleanup;
                received += (size_t)n;
            }

            netbios_length = ((uint32_t)response[1] << 16) |
                             ((uint32_t)response[2] << 8) |
                             (uint32_t)response[3];

            if (response[0] == 0x85 && netbios_length == 0)
                continue;

            if (netbios_length > 0x1ffffu)
                goto cleanup;

            response_length = 4u + (size_t)netbios_length;
            received = 4;

            while (received < response_length) {
                int n = recv(sock, (char *)response + received,
                             (int)(response_length - received), 0);
                if (n == SOCKET_ERROR || n == 0)
                    goto cleanup;
                received += (size_t)n;
            }
            break;
        }

        if (i == 1) {
            if (response_length < 34)
                goto cleanup;
            user_id = (uint16_t)response[32] |
                      (uint16_t)((uint16_t)response[33] << 8);
            tree_connect[32] = response[32];
            tree_connect[33] = response[33];
        } else if (i == 2) {
            if (response_length < 34)
                goto cleanup;
            tree_id = (uint16_t)response[28] |
                      (uint16_t)((uint16_t)response[29] << 8);
            trans_named_pipe[28] = (uint8_t)(tree_id & 0xff);
            trans_named_pipe[29] = (uint8_t)(tree_id >> 8);
            trans_named_pipe[32] = (uint8_t)(user_id & 0xff);
            trans_named_pipe[33] = (uint8_t)(user_id >> 8);
        } else if (i == 3) {
            uint32_t status;
            size_t offset = (size_t)SMB_RESP_NT_STATUS_OFFSET;

            if (offset > response_length || response_length - offset < 4)
                goto cleanup;

            status = (uint32_t)response[offset] |
                     ((uint32_t)response[offset + 1] << 8) |
                     ((uint32_t)response[offset + 2] << 16) |
                     ((uint32_t)response[offset + 3] << 24);
            result = status == (uint32_t)NT_STATUS_INSUFF_SERVER_RESOURCES
                         ? 1
                         : 0;
        }
    }

cleanup:
    free(response);
    closesocket(sock);
    return result;
}