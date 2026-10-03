#include <winsock2.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int doublepulsar_send_all(SOCKET socket_handle, const uint8_t *buffer, size_t length)
{
    size_t sent_total = 0;

    while (sent_total < length) {
        size_t remaining = length - sent_total;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int sent = send(socket_handle, (const char *)buffer + sent_total, chunk, 0);

        if (sent == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEINTR) {
                continue;
            }
            return -1;
        }
        if (sent == 0) {
            return -1;
        }
        sent_total += (size_t)sent;
    }

    return 0;
}

static int doublepulsar_recv_all(SOCKET socket_handle, uint8_t *buffer, size_t length)
{
    size_t received_total = 0;

    while (received_total < length) {
        size_t remaining = length - received_total;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int received = recv(socket_handle, (char *)buffer + received_total, chunk, 0);

        if (received == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEINTR) {
                continue;
            }
            return -1;
        }
        if (received == 0) {
            return -1;
        }
        received_total += (size_t)received;
    }

    return 0;
}

static int doublepulsar_recv_frame(SOCKET socket_handle, uint8_t **frame_out, size_t *length_out)
{
    uint8_t header[4];
    size_t payload_length;
    uint8_t *frame;

    *frame_out = NULL;
    *length_out = 0;

    if (doublepulsar_recv_all(socket_handle, header, sizeof(header)) != 0) {
        return -1;
    }

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];
    if (payload_length > SIZE_MAX - sizeof(header)) {
        return -1;
    }

    frame = (uint8_t *)malloc(sizeof(header) + payload_length);
    if (frame == NULL) {
        return -1;
    }

    memcpy(frame, header, sizeof(header));
    if (payload_length != 0 &&
        doublepulsar_recv_all(socket_handle, frame + sizeof(header), payload_length) != 0) {
        free(frame);
        return -1;
    }

    *frame_out = frame;
    *length_out = sizeof(header) + payload_length;
    return 0;
}

int doublepulsar_check(const char *ip, int port)
{
    SOCKET socket_handle;
    uint8_t negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t ping_packet[sizeof(DP_PING_PKT)];
    uint8_t *response = NULL;
    size_t response_length = 0;
    uint8_t user_id[2];
    uint8_t tree_id[2];
    int result = -1;

    if (ip == NULL) {
        return -1;
    }

    socket_handle = smb_connect(ip, port);
    if (socket_handle == INVALID_SOCKET) {
        return -1;
    }

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    if (doublepulsar_send_all(socket_handle, negotiate_packet,
                              sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        doublepulsar_recv_frame(socket_handle, &response, &response_length) != 0) {
        goto cleanup;
    }
    free(response);
    response = NULL;

    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    if (doublepulsar_send_all(socket_handle, session_setup_packet,
                              sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        doublepulsar_recv_frame(socket_handle, &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length < 34) {
        goto cleanup;
    }
    user_id[0] = response[32];
    user_id[1] = response[33];
    free(response);
    response = NULL;

    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    tree_connect_packet[32] = user_id[0];
    tree_connect_packet[33] = user_id[1];
    if (doublepulsar_send_all(socket_handle, tree_connect_packet,
                              sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        doublepulsar_recv_frame(socket_handle, &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length < 30) {
        goto cleanup;
    }
    tree_id[0] = response[28];
    tree_id[1] = response[29];
    free(response);
    response = NULL;

    memcpy(ping_packet, DP_PING_PKT, sizeof(DP_PING_PKT));
    ping_packet[28] = tree_id[0];
    ping_packet[29] = tree_id[1];
    ping_packet[32] = user_id[0];
    ping_packet[33] = user_id[1];
    if (doublepulsar_send_all(socket_handle, ping_packet,
                              sizeof(DP_PING_PKT) - 1) != 0 ||
        doublepulsar_recv_frame(socket_handle, &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length <= SMB_RESP_MUX_ID_OFFSET) {
        goto cleanup;
    }

    result = response[SMB_RESP_MUX_ID_OFFSET] == DP_MULTIPLEX_ID_PING ? 1 : 0;

cleanup:
    free(response);
    closesocket(socket_handle);
    return result;
}