#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

int ms17_vuln_status(const char *ip, int port)
{
    SOCKET sock = INVALID_SOCKET;
    int result = -1;
    uint8_t negotiate_pkt[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup_pkt[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect_pkt[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t trans_named_pipe_pkt[sizeof(SMB_TRANS_NAMED_PIPE_PKT)];
    uint8_t response[131075];
    const uint8_t *packet;
    size_t packet_len;
    size_t sent;
    size_t received;
    uint32_t response_payload_len;
    uint32_t status;
    int stage;

    if (ip == NULL)
        return -1;

    memcpy(negotiate_pkt, SMB_NEGOTIATE_PKT, sizeof(negotiate_pkt));
    memcpy(session_setup_pkt, SMB_SESSION_SETUP_PKT, sizeof(session_setup_pkt));
    memcpy(tree_connect_pkt, SMB_TREE_CONNECT_PKT, sizeof(tree_connect_pkt));
    memcpy(trans_named_pipe_pkt, SMB_TRANS_NAMED_PIPE_PKT, sizeof(trans_named_pipe_pkt));

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return -1;

    for (stage = 0; stage < 4; ++stage) {
        if (stage == 0) {
            packet = negotiate_pkt;
            packet_len = sizeof(SMB_NEGOTIATE_PKT) - 1;
        } else if (stage == 1) {
            if (sizeof(session_setup_pkt) <= 33 || sizeof(tree_connect_pkt) <= 33)
                goto cleanup;
            tree_connect_pkt[32] = response[32];
            tree_connect_pkt[33] = response[33];
            packet = session_setup_pkt;
            packet_len = sizeof(SMB_SESSION_SETUP_PKT) - 1;
        } else if (stage == 2) {
            if (sizeof(tree_connect_pkt) <= 33 || sizeof(trans_named_pipe_pkt) <= 33)
                goto cleanup;
            trans_named_pipe_pkt[28] = response[28];
            trans_named_pipe_pkt[29] = response[29];
            trans_named_pipe_pkt[32] = response[32];
            trans_named_pipe_pkt[33] = response[33];
            packet = tree_connect_pkt;
            packet_len = sizeof(SMB_TREE_CONNECT_PKT) - 1;
        } else {
            packet = trans_named_pipe_pkt;
            packet_len = sizeof(SMB_TRANS_NAMED_PIPE_PKT) - 1;
        }

        sent = 0;
        while (sent < packet_len) {
            int amount = send(sock, (const char *)packet + sent,
                              (int)(packet_len - sent), 0);
            if (amount == SOCKET_ERROR || amount == 0)
                goto cleanup;
            sent += (size_t)amount;
        }

        received = 0;
        while (received < 4) {
            int amount = recv(sock, (char *)response + received,
                              (int)(4 - received), 0);
            if (amount == SOCKET_ERROR || amount == 0)
                goto cleanup;
            received += (size_t)amount;
        }

        response_payload_len = ((uint32_t)response[1] << 16) |
                               ((uint32_t)response[2] << 8) |
                               (uint32_t)response[3];
        if (response_payload_len > sizeof(response) - 4)
            goto cleanup;

        received = 4;
        while (received < (size_t)response_payload_len + 4) {
            int amount = recv(sock, (char *)response + received,
                              (int)((size_t)response_payload_len + 4 - received), 0);
            if (amount == SOCKET_ERROR || amount == 0)
                goto cleanup;
            received += (size_t)amount;
        }

        if (stage == 1 && received <= 33)
            goto cleanup;
        if (stage == 2 && received <= 33)
            goto cleanup;
        if (stage == 3 &&
            ((size_t)SMB_RESP_NT_STATUS_OFFSET + sizeof(status) > received))
            goto cleanup;
    }

    status = (uint32_t)response[SMB_RESP_NT_STATUS_OFFSET] |
             ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 1] << 8) |
             ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 2] << 16) |
             ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 3] << 24);
    result = status == NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;

cleanup:
    closesocket(sock);
    return result;
}