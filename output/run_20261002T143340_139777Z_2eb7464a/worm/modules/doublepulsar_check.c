#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int doublepulsar_recv_exact(SOCKET socket_handle, unsigned char *buffer, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(socket_handle, (char *)buffer + received, chunk, 0);

        if (result == SOCKET_ERROR || result == 0)
            return -1;

        received += (size_t)result;
    }

    return 0;
}

static int doublepulsar_exchange(SOCKET socket_handle,
                                 const unsigned char *packet,
                                 size_t packet_length,
                                 unsigned char *response,
                                 size_t response_capacity,
                                 size_t *response_length)
{
    size_t sent = 0;
    unsigned char header[4];
    size_t payload_length;
    size_t total_length;

    while (sent < packet_length) {
        size_t remaining = packet_length - sent;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = send(socket_handle, (const char *)packet + sent, chunk, 0);

        if (result == SOCKET_ERROR || result == 0)
            return -1;

        sent += (size_t)result;
    }

    if (doublepulsar_recv_exact(socket_handle, header, sizeof(header)) != 0)
        return -1;

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];

    if (payload_length > SIZE_MAX - sizeof(header))
        return -1;

    total_length = sizeof(header) + payload_length;
    if (total_length > response_capacity || payload_length < 31)
        return -1;

    memcpy(response, header, sizeof(header));
    if (doublepulsar_recv_exact(socket_handle, response + sizeof(header),
                                payload_length) != 0)
        return -1;

    *response_length = total_length;
    return 0;
}

int doublepulsar_check(const char *ip, int port)
{
    SOCKET socket_handle;
    unsigned char negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    unsigned char session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    unsigned char tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    unsigned char ping_packet[sizeof(DP_PING_PKT)];
    unsigned char response[131075];
    size_t response_length = 0;
    unsigned char user_id[2];
    unsigned char tree_id[2];
    int result = -1;

    if (ip == NULL ||
        sizeof(SMB_NEGOTIATE_PKT) < 1 ||
        sizeof(SMB_SESSION_SETUP_PKT) < 1 ||
        sizeof(SMB_TREE_CONNECT_PKT) < 34 ||
        sizeof(DP_PING_PKT) < 34) {
        return -1;
    }

    socket_handle = smb_connect(ip, port);
    if (socket_handle == INVALID_SOCKET)
        return -1;

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    if (doublepulsar_exchange(socket_handle, negotiate_packet,
                              sizeof(SMB_NEGOTIATE_PKT) - 1,
                              response, sizeof(response),
                              &response_length) != 0) {
        goto cleanup;
    }

    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT,
           sizeof(SMB_SESSION_SETUP_PKT));
    if (doublepulsar_exchange(socket_handle, session_setup_packet,
                              sizeof(SMB_SESSION_SETUP_PKT) - 1,
                              response, sizeof(response),
                              &response_length) != 0) {
        goto cleanup;
    }

    user_id[0] = response[32];
    user_id[1] = response[33];

    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT,
           sizeof(SMB_TREE_CONNECT_PKT));
    tree_connect_packet[32] = user_id[0];
    tree_connect_packet[33] = user_id[1];

    if (doublepulsar_exchange(socket_handle, tree_connect_packet,
                              sizeof(SMB_TREE_CONNECT_PKT) - 1,
                              response, sizeof(response),
                              &response_length) != 0) {
        goto cleanup;
    }

    tree_id[0] = response[28];
    tree_id[1] = response[29];
    user_id[0] = response[32];
    user_id[1] = response[33];

    memcpy(ping_packet, DP_PING_PKT, sizeof(DP_PING_PKT));
    ping_packet[28] = tree_id[0];
    ping_packet[29] = tree_id[1];
    ping_packet[32] = user_id[0];
    ping_packet[33] = user_id[1];

    if (doublepulsar_exchange(socket_handle, ping_packet,
                              sizeof(DP_PING_PKT) - 1,
                              response, sizeof(response),
                              &response_length) != 0) {
        goto cleanup;
    }

    if (response_length <= SMB_RESP_MUX_ID_OFFSET)
        goto cleanup;

    result = response[SMB_RESP_MUX_ID_OFFSET] == DP_MULTIPLEX_ID_PING ? 1 : 0;

cleanup:
    closesocket(socket_handle);
    return result;
}