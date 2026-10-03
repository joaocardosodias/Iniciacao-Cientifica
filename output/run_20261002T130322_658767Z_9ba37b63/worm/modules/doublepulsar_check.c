#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int dp_send_receive(SOCKET sock, const uint8_t *packet, size_t packet_size,
                           uint8_t *response, size_t response_capacity)
{
    size_t sent = 0;
    size_t received = 0;
    size_t payload_size;

    while (sent < packet_size) {
        size_t remaining = packet_size - sent;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int n = send(sock, (const char *)packet + sent, chunk, 0);
        if (n == SOCKET_ERROR || n == 0)
            return -1;
        sent += (size_t)n;
    }

    while (received < 4) {
        int n = recv(sock, (char *)response + received, (int)(4 - received), 0);
        if (n == SOCKET_ERROR || n == 0)
            return -1;
        received += (size_t)n;
    }

    payload_size = ((size_t)response[1] << 16) |
                   ((size_t)response[2] << 8) |
                   (size_t)response[3];
    if (payload_size > response_capacity - 4)
        return -1;

    while (received < payload_size + 4) {
        size_t remaining = payload_size + 4 - received;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int n = recv(sock, (char *)response + received, chunk, 0);
        if (n == SOCKET_ERROR || n == 0)
            return -1;
        received += (size_t)n;
    }

    if (received > (size_t)INT_MAX)
        return -1;
    return (int)received;
}

int doublepulsar_check(const char *ip, int port)
{
    SOCKET sock = INVALID_SOCKET;
    uint8_t negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t ping_packet[sizeof(DP_PING_PKT)];
    uint8_t *response = NULL;
    size_t response_capacity = 0x20003u;
    int response_size;
    int result = -1;

    if (ip == NULL || port < 1 || port > 65535)
        return -1;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return -1;

    response = (uint8_t *)malloc(response_capacity);
    if (response == NULL)
        goto cleanup;

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    memcpy(ping_packet, DP_PING_PKT, sizeof(DP_PING_PKT));

    response_size = dp_send_receive(sock, negotiate_packet,
                                    sizeof(SMB_NEGOTIATE_PKT) - 1,
                                    response, response_capacity);
    if (response_size < 0)
        goto cleanup;

    response_size = dp_send_receive(sock, session_setup_packet,
                                    sizeof(SMB_SESSION_SETUP_PKT) - 1,
                                    response, response_capacity);
    if (response_size < 34)
        goto cleanup;

    tree_connect_packet[32] = response[32];
    tree_connect_packet[33] = response[33];

    response_size = dp_send_receive(sock, tree_connect_packet,
                                    sizeof(SMB_TREE_CONNECT_PKT) - 1,
                                    response, response_capacity);
    if (response_size < 34)
        goto cleanup;

    ping_packet[28] = response[28];
    ping_packet[29] = response[29];
    ping_packet[32] = tree_connect_packet[32];
    ping_packet[33] = tree_connect_packet[33];

    response_size = dp_send_receive(sock, ping_packet,
                                    sizeof(DP_PING_PKT) - 1,
                                    response, response_capacity);
    if (response_size <= SMB_RESP_MUX_ID_OFFSET)
        goto cleanup;

    result = response[SMB_RESP_MUX_ID_OFFSET] == DP_MULTIPLEX_ID_PING ? 1 : 0;

cleanup:
    free(response);
    closesocket(sock);
    return result;
}