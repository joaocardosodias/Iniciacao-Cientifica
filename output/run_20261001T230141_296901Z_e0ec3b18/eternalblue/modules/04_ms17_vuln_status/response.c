#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int ms17_send_all(SOCKET sock, const uint8_t *data, size_t length)
{
    size_t sent = 0;

    if (length > INT_MAX)
        return -1;

    while (sent < length) {
        int result = send(sock, (const char *)data + sent,
                          (int)(length - sent), 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        sent += (size_t)result;
    }

    return 0;
}

static int ms17_recv_exact(SOCKET sock, uint8_t *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        int result = recv(sock, (char *)data + received,
                          (int)((length - received) > INT_MAX
                                    ? INT_MAX
                                    : (length - received)),
                          0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        received += (size_t)result;
    }

    return 0;
}

static int ms17_recv_packet(SOCKET sock, uint8_t **packet, size_t *packet_length)
{
    uint8_t header[4];
    size_t payload_length;
    uint8_t *buffer;

    if (ms17_recv_exact(sock, header, sizeof(header)) != 0)
        return -1;

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];

    if (payload_length > SIZE_MAX - sizeof(header))
        return -1;

    buffer = (uint8_t *)malloc(sizeof(header) + payload_length);
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (payload_length != 0 &&
        ms17_recv_exact(sock, buffer + sizeof(header), payload_length) != 0) {
        free(buffer);
        return -1;
    }

    *packet = buffer;
    *packet_length = sizeof(header) + payload_length;
    return 0;
}

int ms17_vuln_status(const char *ip, int port)
{
    SOCKET sock = INVALID_SOCKET;
    uint8_t negotiate[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t trans_named_pipe[sizeof(SMB_TRANS_NAMED_PIPE_PKT)];
    uint8_t *response = NULL;
    size_t response_length = 0;
    uint32_t status;
    int result = -1;

    if (ip == NULL)
        return -1;

    memcpy(negotiate, SMB_NEGOTIATE_PKT, sizeof(negotiate));
    memcpy(session_setup, SMB_SESSION_SETUP_PKT, sizeof(session_setup));
    memcpy(tree_connect, SMB_TREE_CONNECT_PKT, sizeof(tree_connect));
    memcpy(trans_named_pipe, SMB_TRANS_NAMED_PIPE_PKT,
           sizeof(trans_named_pipe));

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return -1;

    if (ms17_send_all(sock, negotiate, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        ms17_recv_packet(sock, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (ms17_send_all(sock, session_setup,
                      sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        ms17_recv_packet(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 34)
        goto cleanup;
    memcpy(tree_connect + 32, response + 32, 2);
    free(response);
    response = NULL;

    if (ms17_send_all(sock, tree_connect,
                      sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        ms17_recv_packet(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 34)
        goto cleanup;
    memcpy(trans_named_pipe + 28, response + 28, 2);
    memcpy(trans_named_pipe + 32, response + 32, 2);
    free(response);
    response = NULL;

    if (ms17_send_all(sock, trans_named_pipe,
                      sizeof(SMB_TRANS_NAMED_PIPE_PKT) - 1) != 0 ||
        ms17_recv_packet(sock, &response, &response_length) != 0)
        goto cleanup;

    if ((size_t)SMB_RESP_NT_STATUS_OFFSET > response_length ||
        response_length - (size_t)SMB_RESP_NT_STATUS_OFFSET < 4)
        goto cleanup;

    status = (uint32_t)response[SMB_RESP_NT_STATUS_OFFSET] |
             ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 1] << 8) |
             ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 2] << 16) |
             ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 3] << 24);

    result = status == (uint32_t)NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;

cleanup:
    free(response);
    closesocket(sock);
    return result;
}