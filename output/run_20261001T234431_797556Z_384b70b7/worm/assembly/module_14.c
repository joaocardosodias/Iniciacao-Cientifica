#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <limits.h>
#include <math.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int doublepulsar_send_all(SOCKET sock, const uint8_t *data, size_t length)
{
    size_t sent_total = 0;

    while (sent_total < length) {
        size_t remaining = length - sent_total;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int sent = send(sock, (const char *)data + sent_total, chunk, 0);

        if (sent == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEINTR)
                continue;
            return -1;
        }
        if (sent == 0)
            return -1;

        sent_total += (size_t)sent;
    }

    return 0;
}

static int doublepulsar_recv_exact(SOCKET sock, uint8_t *buffer, size_t length)
{
    size_t received_total = 0;

    while (received_total < length) {
        size_t remaining = length - received_total;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int received = recv(sock, (char *)buffer + received_total, chunk, 0);

        if (received == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEINTR)
                continue;
            return -1;
        }
        if (received == 0)
            return -1;

        received_total += (size_t)received;
    }

    return 0;
}

static int doublepulsar_recv_response(SOCKET sock, uint8_t **response, size_t *response_length)
{
    uint8_t header[4];
    size_t payload_length;
    size_t total_length;
    uint8_t *buffer;

    *response = NULL;
    *response_length = 0;

    if (doublepulsar_recv_exact(sock, header, sizeof(header)) != 0)
        return -1;

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];
    total_length = sizeof(header) + payload_length;

    if (total_length <= SMB_RESP_MUX_ID_OFFSET)
        return -1;

    buffer = (uint8_t *)malloc(total_length);
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (doublepulsar_recv_exact(sock, buffer + sizeof(header), payload_length) != 0) {
        free(buffer);
        return -1;
    }

    *response = buffer;
    *response_length = total_length;
    return 0;
}

int doublepulsar_check(const char *ip, int port)
{
    SOCKET sock;
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

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    if (doublepulsar_send_all(sock, negotiate_packet, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        doublepulsar_recv_response(sock, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    if (doublepulsar_send_all(sock, session_setup_packet, sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        doublepulsar_recv_response(sock, &response, &response_length) != 0)
        goto cleanup;

    if (response_length <= 33)
        goto cleanup;
    session_setup_packet[32] = response[32];
    session_setup_packet[33] = response[33];
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    tree_connect_packet[32] = response[32];
    tree_connect_packet[33] = response[33];
    free(response);
    response = NULL;

    if (doublepulsar_send_all(sock, tree_connect_packet, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        doublepulsar_recv_response(sock, &response, &response_length) != 0)
        goto cleanup;

    if (response_length <= 33)
        goto cleanup;
    memcpy(ping_packet, DP_PING_PKT, sizeof(DP_PING_PKT));
    ping_packet[28] = response[28];
    ping_packet[29] = response[29];
    ping_packet[32] = tree_connect_packet[32];
    ping_packet[33] = tree_connect_packet[33];
    free(response);
    response = NULL;

    if (doublepulsar_send_all(sock, ping_packet, sizeof(DP_PING_PKT) - 1) != 0 ||
        doublepulsar_recv_response(sock, &response, &response_length) != 0)
        goto cleanup;

    result = response[SMB_RESP_MUX_ID_OFFSET] == DP_MULTIPLEX_ID_PING ? 1 : 0;

cleanup:
    free(response);
    closesocket(sock);
    return result;
}