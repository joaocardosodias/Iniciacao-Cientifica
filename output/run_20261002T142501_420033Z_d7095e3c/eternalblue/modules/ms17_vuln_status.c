#include <winsock2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
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

static int smb_recv_all(SOCKET sock, uint8_t *data, size_t length)
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

static int smb_recv_response(SOCKET sock, uint8_t **response, size_t *response_length)
{
    uint8_t header[4];
    size_t body_length;
    uint8_t *buffer;

    *response = NULL;
    *response_length = 0;

    if (smb_recv_all(sock, header, sizeof(header)) != 0) {
        return -1;
    }

    body_length = ((size_t)header[1] << 16) |
                  ((size_t)header[2] << 8) |
                  (size_t)header[3];

    buffer = (uint8_t *)malloc(sizeof(header) + body_length);
    if (buffer == NULL) {
        return -1;
    }

    memcpy(buffer, header, sizeof(header));
    if (body_length != 0 &&
        smb_recv_all(sock, buffer + sizeof(header), body_length) != 0) {
        free(buffer);
        return -1;
    }

    *response = buffer;
    *response_length = sizeof(header) + body_length;
    return 0;
}

int ms17_vuln_status(const char *ip, int port)
{
    SOCKET sock = INVALID_SOCKET;
    uint8_t *negotiate = NULL;
    uint8_t *session_setup = NULL;
    uint8_t *tree_connect = NULL;
    uint8_t *trans_named_pipe = NULL;
    uint8_t *response = NULL;
    size_t response_length = 0;
    uint16_t user_id;
    uint16_t tree_id;
    uint32_t nt_status;
    int result = -1;

    if (ip == NULL) {
        return -1;
    }

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    negotiate = (uint8_t *)malloc(sizeof(SMB_NEGOTIATE_PKT));
    session_setup = (uint8_t *)malloc(sizeof(SMB_SESSION_SETUP_PKT));
    tree_connect = (uint8_t *)malloc(sizeof(SMB_TREE_CONNECT_PKT));
    trans_named_pipe = (uint8_t *)malloc(sizeof(SMB_TRANS_NAMED_PIPE_PKT));
    if (negotiate == NULL || session_setup == NULL || tree_connect == NULL ||
        trans_named_pipe == NULL) {
        goto cleanup;
    }

    memcpy(negotiate, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    memcpy(session_setup, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    memcpy(tree_connect, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    memcpy(trans_named_pipe, SMB_TRANS_NAMED_PIPE_PKT,
           sizeof(SMB_TRANS_NAMED_PIPE_PKT));

    if (smb_send_all(sock, negotiate, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        smb_recv_response(sock, &response, &response_length) != 0) {
        goto cleanup;
    }
    free(response);
    response = NULL;

    if (smb_send_all(sock, session_setup, sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        smb_recv_response(sock, &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length < 34) {
        goto cleanup;
    }
    user_id = (uint16_t)response[32] | ((uint16_t)response[33] << 8);
    free(response);
    response = NULL;

    if (sizeof(SMB_TREE_CONNECT_PKT) < 34) {
        goto cleanup;
    }
    tree_connect[32] = (uint8_t)(user_id & 0xff);
    tree_connect[33] = (uint8_t)(user_id >> 8);

    if (smb_send_all(sock, tree_connect, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        smb_recv_response(sock, &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length < 34) {
        goto cleanup;
    }
    tree_id = (uint16_t)response[28] | ((uint16_t)response[29] << 8);
    free(response);
    response = NULL;

    if (sizeof(SMB_TRANS_NAMED_PIPE_PKT) < 34) {
        goto cleanup;
    }
    trans_named_pipe[28] = (uint8_t)(tree_id & 0xff);
    trans_named_pipe[29] = (uint8_t)(tree_id >> 8);
    trans_named_pipe[32] = (uint8_t)(user_id & 0xff);
    trans_named_pipe[33] = (uint8_t)(user_id >> 8);

    if (smb_send_all(sock, trans_named_pipe,
                     sizeof(SMB_TRANS_NAMED_PIPE_PKT) - 1) != 0 ||
        smb_recv_response(sock, &response, &response_length) != 0) {
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
    free(negotiate);
    free(session_setup);
    free(tree_connect);
    free(trans_named_pipe);
    if (sock != INVALID_SOCKET) {
        closesocket(sock);
    }
    return result;
}