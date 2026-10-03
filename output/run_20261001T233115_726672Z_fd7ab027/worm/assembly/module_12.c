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

static int smb_send_all(SOCKET sock, const uint8_t *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        size_t remaining = length - sent;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = send(sock, (const char *)data + sent, chunk, 0);

        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        sent += (size_t)result;
    }

    return 0;
}

static int smb_recv_frame(SOCKET sock, uint8_t **frame_out, size_t *frame_length_out)
{
    uint8_t header[4];
    size_t received = 0;
    uint32_t payload_length;
    size_t frame_length;
    uint8_t *frame;

    while (received < sizeof(header)) {
        int result = recv(sock, (char *)header + received,
                          (int)(sizeof(header) - received), 0);
        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        received += (size_t)result;
    }

    payload_length = ((uint32_t)header[1] << 16) |
                     ((uint32_t)header[2] << 8) |
                     (uint32_t)header[3];
    frame_length = sizeof(header) + (size_t)payload_length;

    frame = (uint8_t *)malloc(frame_length);
    if (frame == NULL) {
        return -1;
    }
    memcpy(frame, header, sizeof(header));

    received = sizeof(header);
    while (received < frame_length) {
        size_t remaining = frame_length - received;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)frame + received, chunk, 0);

        if (result == SOCKET_ERROR || result == 0) {
            free(frame);
            return -1;
        }
        received += (size_t)result;
    }

    *frame_out = frame;
    *frame_length_out = frame_length;
    return 0;
}

int ms17_vuln_status(const char *ip, int port)
{
    SOCKET sock = INVALID_SOCKET;
    uint8_t negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t trans_named_pipe_packet[sizeof(SMB_TRANS_NAMED_PIPE_PKT)];
    uint8_t *response = NULL;
    size_t response_length = 0;
    uint32_t status;
    int result = -1;

    if (ip == NULL) {
        return -1;
    }

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    memcpy(trans_named_pipe_packet, SMB_TRANS_NAMED_PIPE_PKT,
           sizeof(SMB_TRANS_NAMED_PIPE_PKT));

    if (smb_send_all(sock, negotiate_packet, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        smb_recv_frame(sock, &response, &response_length) != 0) {
        goto cleanup;
    }
    free(response);
    response = NULL;

    if (smb_send_all(sock, session_setup_packet, sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        smb_recv_frame(sock, &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length < 34) {
        goto cleanup;
    }
    tree_connect_packet[32] = response[32];
    tree_connect_packet[33] = response[33];
    free(response);
    response = NULL;

    if (smb_send_all(sock, tree_connect_packet, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        smb_recv_frame(sock, &response, &response_length) != 0) {
        goto cleanup;
    }
    if (response_length < 34) {
        goto cleanup;
    }
    trans_named_pipe_packet[28] = response[28];
    trans_named_pipe_packet[29] = response[29];
    trans_named_pipe_packet[32] = response[32];
    trans_named_pipe_packet[33] = response[33];
    free(response);
    response = NULL;

    if (smb_send_all(sock, trans_named_pipe_packet,
                     sizeof(SMB_TRANS_NAMED_PIPE_PKT) - 1) != 0 ||
        smb_recv_frame(sock, &response, &response_length) != 0) {
        goto cleanup;
    }

    if ((size_t)SMB_RESP_NT_STATUS_OFFSET > response_length ||
        response_length - (size_t)SMB_RESP_NT_STATUS_OFFSET < 4) {
        goto cleanup;
    }

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