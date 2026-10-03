#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int doublepulsar_send_all(SOCKET sock, const uint8_t *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        size_t remaining = length - sent;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = send(sock, (const char *)(data + sent), chunk, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        sent += (size_t)result;
    }

    return 0;
}

static int doublepulsar_recv_exact(SOCKET sock, uint8_t *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)(data + received), chunk, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        received += (size_t)result;
    }

    return 0;
}

static int doublepulsar_recv_smb_response(SOCKET sock, uint8_t **response,
                                           size_t *response_length)
{
    uint8_t header[4];
    size_t payload_length;
    uint8_t *buffer;

    *response = NULL;
    *response_length = 0;

    if (doublepulsar_recv_exact(sock, header, sizeof(header)) != 0)
        return -1;

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];

    buffer = (uint8_t *)malloc(sizeof(header) + payload_length);
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (payload_length != 0 &&
        doublepulsar_recv_exact(sock, buffer + sizeof(header), payload_length) != 0) {
        free(buffer);
        return -1;
    }

    *response = buffer;
    *response_length = sizeof(header) + payload_length;
    return 0;
}

int doublepulsar_check(const char *ip, int port)
{
    SOCKET sock = INVALID_SOCKET;
    uint8_t negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t ping_packet[sizeof(DP_PING_PKT)];
    uint8_t *response = NULL;
    size_t response_length = 0;
    int result = -1;

    if (ip == NULL)
        return -1;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return -1;

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(negotiate_packet));
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(session_setup_packet));
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(tree_connect_packet));
    memcpy(ping_packet, DP_PING_PKT, sizeof(ping_packet));

    if (doublepulsar_send_all(sock, negotiate_packet,
                              sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        doublepulsar_recv_smb_response(sock, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (doublepulsar_send_all(sock, session_setup_packet,
                              sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        doublepulsar_recv_smb_response(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length <= 33)
        goto cleanup;

    memcpy(tree_connect_packet + 32, response + 32, 2);
    free(response);
    response = NULL;

    if (doublepulsar_send_all(sock, tree_connect_packet,
                              sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        doublepulsar_recv_smb_response(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length <= 29)
        goto cleanup;

    memcpy(ping_packet + 28, response + 28, 2);
    memcpy(ping_packet + 32, response_length > 33 ? response + 32 : tree_connect_packet + 32, 2);
    free(response);
    response = NULL;

    if (doublepulsar_send_all(sock, ping_packet, sizeof(DP_PING_PKT) - 1) != 0 ||
        doublepulsar_recv_smb_response(sock, &response, &response_length) != 0)
        goto cleanup;

    if (response_length > SMB_RESP_MUX_ID_OFFSET)
        result = response[SMB_RESP_MUX_ID_OFFSET] == DP_MULTIPLEX_ID_PING ? 1 : 0;

cleanup:
    free(response);
    closesocket(sock);
    return result;
}