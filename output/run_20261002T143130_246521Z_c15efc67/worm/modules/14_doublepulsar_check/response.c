#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int doublepulsar_send_all(SOCKET socket_handle, const unsigned char *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        int chunk = (int)(length - sent);
        int result = send(socket_handle, (const char *)data + sent, chunk, 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        sent += (size_t)result;
    }

    return 0;
}

static int doublepulsar_recv_frame(SOCKET socket_handle, unsigned char **frame, size_t *frame_length)
{
    unsigned char header[4];
    size_t received = 0;
    size_t payload_length;
    unsigned char *buffer;

    while (received < sizeof(header)) {
        int result = recv(socket_handle, (char *)header + received,
                          (int)(sizeof(header) - received), 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        received += (size_t)result;
    }

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];
    buffer = (unsigned char *)malloc(sizeof(header) + payload_length);
    if (buffer == NULL) {
        return -1;
    }

    memcpy(buffer, header, sizeof(header));
    received = 0;
    while (received < payload_length) {
        size_t remaining = payload_length - received;
        int chunk = remaining > (size_t)0x7fffffff ? 0x7fffffff : (int)remaining;
        int result = recv(socket_handle, (char *)buffer + sizeof(header) + received,
                          chunk, 0);
        if (result == SOCKET_ERROR || result == 0) {
            free(buffer);
            return -1;
        }
        received += (size_t)result;
    }

    *frame = buffer;
    *frame_length = sizeof(header) + payload_length;
    return 0;
}

int doublepulsar_check(const char *ip, int port)
{
    SOCKET socket_handle;
    unsigned char negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    unsigned char session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    unsigned char tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    unsigned char ping_packet[sizeof(DP_PING_PKT)];
    unsigned char *response = NULL;
    size_t response_length = 0;
    unsigned char user_id[2];
    unsigned char tree_id[2];
    int result = -1;

    if (ip == NULL) {
        return -1;
    }

    socket_handle = smb_connect(ip, port);
    if (socket_handle == INVALID_SOCKET) {
        return -1;
    }

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(negotiate_packet));
    if (doublepulsar_send_all(socket_handle, negotiate_packet,
                              sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        doublepulsar_recv_frame(socket_handle, &response, &response_length) != 0) {
        goto cleanup;
    }
    free(response);
    response = NULL;

    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(session_setup_packet));
    if (doublepulsar_send_all(socket_handle, session_setup_packet,
                              sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        doublepulsar_recv_frame(socket_handle, &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length <= 33) {
        goto cleanup;
    }
    user_id[0] = response[32];
    user_id[1] = response[33];
    free(response);
    response = NULL;

    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(tree_connect_packet));
    tree_connect_packet[32] = user_id[0];
    tree_connect_packet[33] = user_id[1];
    if (doublepulsar_send_all(socket_handle, tree_connect_packet,
                              sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        doublepulsar_recv_frame(socket_handle, &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length <= 29) {
        goto cleanup;
    }
    tree_id[0] = response[28];
    tree_id[1] = response[29];
    free(response);
    response = NULL;

    memcpy(ping_packet, DP_PING_PKT, sizeof(ping_packet));
    ping_packet[28] = tree_id[0];
    ping_packet[29] = tree_id[1];
    ping_packet[32] = user_id[0];
    ping_packet[33] = user_id[1];
    if (doublepulsar_send_all(socket_handle, ping_packet,
                              sizeof(DP_PING_PKT) - 1) != 0 ||
        doublepulsar_recv_frame(socket_handle, &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length <= (size_t)SMB_RESP_MUX_ID_OFFSET) {
        goto cleanup;
    }

    result = response[SMB_RESP_MUX_ID_OFFSET] == DP_MULTIPLEX_ID_PING ? 1 : 0;

cleanup:
    free(response);
    closesocket(socket_handle);
    return result;
}