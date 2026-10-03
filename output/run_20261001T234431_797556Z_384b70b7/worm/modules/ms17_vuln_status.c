#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int smb_send_all(SOCKET sock, const uint8_t *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        size_t remaining = length - sent;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = send(sock, (const char *)data + sent, chunk, 0);

        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        sent += (size_t)result;
    }

    return 0;
}

static int smb_recv_exact(SOCKET sock, uint8_t *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)data + received, chunk, 0);

        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        received += (size_t)result;
    }

    return 0;
}

static int smb_recv_packet(SOCKET sock, uint8_t **packet, size_t *packet_length)
{
    uint8_t header[4];
    uint32_t payload_length;
    uint8_t *buffer;

    *packet = NULL;
    *packet_length = 0;

    if (smb_recv_exact(sock, header, sizeof(header)) != 0) {
        return -1;
    }

    payload_length = ((uint32_t)header[1] << 16) |
                     ((uint32_t)header[2] << 8) |
                     (uint32_t)header[3];

    buffer = (uint8_t *)malloc((size_t)payload_length + sizeof(header));
    if (buffer == NULL) {
        return -1;
    }

    memcpy(buffer, header, sizeof(header));
    if (payload_length != 0 &&
        smb_recv_exact(sock, buffer + sizeof(header), payload_length) != 0) {
        free(buffer);
        return -1;
    }

    *packet = buffer;
    *packet_length = (size_t)payload_length + sizeof(header);
    return 0;
}

int ms17_vuln_status(const char *ip, int port)
{
    uint8_t negotiate_pkt[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup_pkt[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect_pkt[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t trans_named_pipe_pkt[sizeof(SMB_TRANS_NAMED_PIPE_PKT)];
    SOCKET sock;
    uint8_t *response = NULL;
    size_t response_length = 0;
    uint8_t user_id[2];
    uint8_t tree_id[2];
    uint32_t nt_status;
    int result = -1;

    memcpy(negotiate_pkt, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    memcpy(session_setup_pkt, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    memcpy(tree_connect_pkt, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    memcpy(trans_named_pipe_pkt, SMB_TRANS_NAMED_PIPE_PKT, sizeof(SMB_TRANS_NAMED_PIPE_PKT));

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    if (smb_send_all(sock, negotiate_pkt, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        smb_recv_packet(sock, &response, &response_length) != 0) {
        goto cleanup;
    }
    free(response);
    response = NULL;

    if (smb_send_all(sock, session_setup_pkt, sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        smb_recv_packet(sock, &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length <= 33) {
        goto cleanup;
    }
    user_id[0] = response[32];
    user_id[1] = response[33];
    free(response);
    response = NULL;

    tree_connect_pkt[32] = user_id[0];
    tree_connect_pkt[33] = user_id[1];
    if (smb_send_all(sock, tree_connect_pkt, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        smb_recv_packet(sock, &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length <= 29) {
        goto cleanup;
    }
    tree_id[0] = response[28];
    tree_id[1] = response[29];
    free(response);
    response = NULL;

    trans_named_pipe_pkt[28] = tree_id[0];
    trans_named_pipe_pkt[29] = tree_id[1];
    trans_named_pipe_pkt[32] = user_id[0];
    trans_named_pipe_pkt[33] = user_id[1];
    if (smb_send_all(sock, trans_named_pipe_pkt, sizeof(SMB_TRANS_NAMED_PIPE_PKT) - 1) != 0 ||
        smb_recv_packet(sock, &response, &response_length) != 0) {
        goto cleanup;
    }

    if (response_length < (size_t)SMB_RESP_NT_STATUS_OFFSET + sizeof(uint32_t)) {
        goto cleanup;
    }

    nt_status = (uint32_t)response[SMB_RESP_NT_STATUS_OFFSET] |
                ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 1] << 8) |
                ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 2] << 16) |
                ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 3] << 24);
    result = nt_status == NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;

cleanup:
    free(response);
    closesocket(sock);
    return result;
}