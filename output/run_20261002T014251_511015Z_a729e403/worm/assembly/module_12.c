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
#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int ms17_send_all(SOCKET sock, const uint8_t *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        size_t remaining = length - sent;
        int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
        int result = send(sock, (const char *)data + sent, chunk, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        sent += (size_t)result;
    }

    return 0;
}

static int ms17_recv_exact(SOCKET sock, uint8_t *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)data + received, chunk, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        received += (size_t)result;
    }

    return 0;
}

static int ms17_recv_frame(SOCKET sock, uint8_t **frame, size_t *frame_length)
{
    uint8_t header[4];
    size_t payload_length;
    size_t total_length;
    uint8_t *buffer;

    if (ms17_recv_exact(sock, header, sizeof(header)) != 0)
        return -1;

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];
    total_length = sizeof(header) + payload_length;

    buffer = (uint8_t *)malloc(total_length);
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (payload_length != 0 &&
        ms17_recv_exact(sock, buffer + sizeof(header), payload_length) != 0) {
        free(buffer);
        return -1;
    }

    *frame = buffer;
    *frame_length = total_length;
    return 0;
}

int ms17_vuln_status(const char *ip, int port)
{
    uint8_t negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t trans_named_pipe_packet[sizeof(SMB_TRANS_NAMED_PIPE_PKT)];
    uint8_t *response = NULL;
    size_t response_length = 0;
    uint32_t nt_status;
    SOCKET sock;
    int result = -1;

    if (ip == NULL || port <= 0 || port > 65535)
        return -1;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return -1;

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(negotiate_packet));
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(session_setup_packet));
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(tree_connect_packet));
    memcpy(trans_named_pipe_packet, SMB_TRANS_NAMED_PIPE_PKT,
           sizeof(trans_named_pipe_packet));

    if (ms17_send_all(sock, negotiate_packet,
                      sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        ms17_recv_frame(sock, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (ms17_send_all(sock, session_setup_packet,
                      sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        ms17_recv_frame(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 34)
        goto cleanup;
    session_setup_packet[32] = response[32];
    session_setup_packet[33] = response[33];
    tree_connect_packet[32] = response[32];
    tree_connect_packet[33] = response[33];
    free(response);
    response = NULL;

    if (ms17_send_all(sock, tree_connect_packet,
                      sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        ms17_recv_frame(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 34)
        goto cleanup;
    trans_named_pipe_packet[28] = response[28];
    trans_named_pipe_packet[29] = response[29];
    trans_named_pipe_packet[32] = tree_connect_packet[32];
    trans_named_pipe_packet[33] = tree_connect_packet[33];
    free(response);
    response = NULL;

    if (ms17_send_all(sock, trans_named_pipe_packet,
                      sizeof(SMB_TRANS_NAMED_PIPE_PKT) - 1) != 0 ||
        ms17_recv_frame(sock, &response, &response_length) != 0)
        goto cleanup;

    if ((size_t)SMB_RESP_NT_STATUS_OFFSET > response_length ||
        response_length - (size_t)SMB_RESP_NT_STATUS_OFFSET < 4)
        goto cleanup;

    nt_status = (uint32_t)response[SMB_RESP_NT_STATUS_OFFSET] |
                ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 1] << 8) |
                ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 2] << 16) |
                ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 3] << 24);
    result = nt_status == NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;

cleanup:
    free(response);
    closesocket(sock);
    return result;
}