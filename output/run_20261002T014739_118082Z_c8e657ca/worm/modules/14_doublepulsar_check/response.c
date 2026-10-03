#include <winsock2.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int dp_send_all(SOCKET sock, const uint8_t *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        size_t remaining = length - sent;
        int chunk = remaining > 0x7fffffffU ? 0x7fffffff : (int)remaining;
        int result = send(sock, (const char *)data + sent, chunk, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        sent += (size_t)result;
    }

    return 0;
}

static int dp_recv_exact(SOCKET sock, uint8_t *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int chunk = remaining > 0x7fffffffU ? 0x7fffffff : (int)remaining;
        int result = recv(sock, (char *)data + received, chunk, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        received += (size_t)result;
    }

    return 0;
}

static int dp_recv_response(SOCKET sock, uint8_t **response, size_t *response_length)
{
    for (;;) {
        uint8_t header[4];
        uint32_t payload_length;
        uint8_t *frame;

        if (dp_recv_exact(sock, header, sizeof(header)) != 0)
            return -1;

        payload_length = ((uint32_t)header[1] << 16) |
                         ((uint32_t)header[2] << 8) |
                         (uint32_t)header[3];

        if ((size_t)payload_length > SIZE_MAX - sizeof(header))
            return -1;

        frame = (uint8_t *)malloc((size_t)payload_length + sizeof(header));
        if (frame == NULL)
            return -1;

        memcpy(frame, header, sizeof(header));
        if (payload_length != 0 &&
            dp_recv_exact(sock, frame + sizeof(header), payload_length) != 0) {
            free(frame);
            return -1;
        }

        if (header[0] == 0x85) {
            free(frame);
            continue;
        }

        *response = frame;
        *response_length = (size_t)payload_length + sizeof(header);
        return 0;
    }
}

int doublepulsar_check(const char *ip, int port)
{
    SOCKET sock = INVALID_SOCKET;
    uint8_t negotiate[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t ping[sizeof(DP_PING_PKT)];
    uint8_t *response = NULL;
    size_t response_length = 0;
    int result = -1;

    if (ip == NULL)
        return -1;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return -1;

    memcpy(negotiate, SMB_NEGOTIATE_PKT, sizeof(negotiate));
    if (dp_send_all(sock, negotiate, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        dp_recv_response(sock, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    memcpy(session_setup, SMB_SESSION_SETUP_PKT, sizeof(session_setup));
    if (dp_send_all(sock, session_setup, sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        dp_recv_response(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 34)
        goto cleanup;

    memcpy(tree_connect, SMB_TREE_CONNECT_PKT, sizeof(tree_connect));
    tree_connect[32] = response[32];
    tree_connect[33] = response[33];
    free(response);
    response = NULL;

    if (dp_send_all(sock, tree_connect, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        dp_recv_response(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 30)
        goto cleanup;

    memcpy(ping, DP_PING_PKT, sizeof(ping));
    ping[28] = response[28];
    ping[29] = response[29];
    ping[32] = tree_connect[32];
    ping[33] = tree_connect[33];
    free(response);
    response = NULL;

    if (dp_send_all(sock, ping, sizeof(DP_PING_PKT) - 1) != 0 ||
        dp_recv_response(sock, &response, &response_length) != 0)
        goto cleanup;

    if (response_length <= SMB_RESP_MUX_ID_OFFSET)
        goto cleanup;

    result = response[SMB_RESP_MUX_ID_OFFSET] == DP_MULTIPLEX_ID_PING ? 1 : 0;

cleanup:
    free(response);
    closesocket(sock);
    return result;
}