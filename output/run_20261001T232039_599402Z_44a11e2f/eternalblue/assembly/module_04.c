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
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int ms17_send_all(SOCKET sock, const uint8_t *data, size_t length)
{
    size_t sent_total = 0;

    while (sent_total < length) {
        size_t remaining = length - sent_total;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int sent = send(sock, (const char *)data + sent_total, chunk, 0);

        if (sent == SOCKET_ERROR || sent == 0)
            return -1;

        sent_total += (size_t)sent;
    }

    return 0;
}

static int ms17_recv_all(SOCKET sock, uint8_t *data, size_t length)
{
    size_t received_total = 0;

    while (received_total < length) {
        size_t remaining = length - received_total;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int received = recv(sock, (char *)data + received_total, chunk, 0);

        if (received == SOCKET_ERROR || received == 0)
            return -1;

        received_total += (size_t)received;
    }

    return 0;
}

static int ms17_read_response(SOCKET sock, uint8_t **response, size_t *response_length)
{
    uint8_t header[4];
    uint32_t payload_length;
    uint8_t *buffer;

    *response = NULL;
    *response_length = 0;

    if (ms17_recv_all(sock, header, sizeof(header)) != 0)
        return -1;

    payload_length = ((uint32_t)header[1] << 16) |
                     ((uint32_t)header[2] << 8) |
                     (uint32_t)header[3];

    if ((size_t)payload_length > SIZE_MAX - sizeof(header))
        return -1;

    buffer = (uint8_t *)malloc(sizeof(header) + (size_t)payload_length);
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (payload_length != 0 &&
        ms17_recv_all(sock, buffer + sizeof(header), (size_t)payload_length) != 0) {
        free(buffer);
        return -1;
    }

    *response = buffer;
    *response_length = sizeof(header) + (size_t)payload_length;
    return 0;
}

int ms17_vuln_status(const char *ip, int port)
{
    SOCKET sock;
    uint8_t negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t trans_named_pipe_packet[sizeof(SMB_TRANS_NAMED_PIPE_PKT)];
    uint8_t *response = NULL;
    size_t response_length = 0;
    uint16_t user_id;
    uint16_t tree_id;
    uint32_t status;
    int result = -1;

    if (ip == NULL || port <= 0 || port > 65535)
        return -1;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return -1;

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(negotiate_packet));
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(session_setup_packet));
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(tree_connect_packet));
    memcpy(trans_named_pipe_packet, SMB_TRANS_NAMED_PIPE_PKT, sizeof(trans_named_pipe_packet));

    if (ms17_send_all(sock, negotiate_packet, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        ms17_read_response(sock, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (ms17_send_all(sock, session_setup_packet, sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        ms17_read_response(sock, &response, &response_length) != 0)
        goto cleanup;

    if (response_length < 34)
        goto cleanup;
    user_id = (uint16_t)response[32] | ((uint16_t)response[33] << 8);
    free(response);
    response = NULL;

    if (sizeof(tree_connect_packet) < 34)
        goto cleanup;
    tree_connect_packet[32] = (uint8_t)(user_id & 0xff);
    tree_connect_packet[33] = (uint8_t)(user_id >> 8);

    if (ms17_send_all(sock, tree_connect_packet, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        ms17_read_response(sock, &response, &response_length) != 0)
        goto cleanup;

    if (response_length < 34)
        goto cleanup;
    tree_id = (uint16_t)response[28] | ((uint16_t)response[29] << 8);
    free(response);
    response = NULL;

    if (sizeof(trans_named_pipe_packet) < 34)
        goto cleanup;
    trans_named_pipe_packet[28] = (uint8_t)(tree_id & 0xff);
    trans_named_pipe_packet[29] = (uint8_t)(tree_id >> 8);
    trans_named_pipe_packet[32] = (uint8_t)(user_id & 0xff);
    trans_named_pipe_packet[33] = (uint8_t)(user_id >> 8);

    if (ms17_send_all(sock, trans_named_pipe_packet, sizeof(SMB_TRANS_NAMED_PIPE_PKT) - 1) != 0 ||
        ms17_read_response(sock, &response, &response_length) != 0)
        goto cleanup;

    if (response_length < (size_t)SMB_RESP_NT_STATUS_OFFSET + 4)
        goto cleanup;

    status = (uint32_t)response[SMB_RESP_NT_STATUS_OFFSET] |
             ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 1] << 8) |
             ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 2] << 16) |
             ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 3] << 24);

    result = status == NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;

cleanup:
    free(response);
    closesocket(sock);
    return result;
}