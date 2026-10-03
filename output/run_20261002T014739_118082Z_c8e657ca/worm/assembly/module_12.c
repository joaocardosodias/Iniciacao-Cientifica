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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int smb_send_all(SOCKET socket_handle, const uint8_t *data, size_t length)
{
    size_t sent_total = 0;

    while (sent_total < length) {
        size_t remaining = length - sent_total;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int sent = send(socket_handle, (const char *)data + sent_total, chunk, 0);

        if (sent == SOCKET_ERROR || sent == 0)
            return -1;

        sent_total += (size_t)sent;
    }

    return 0;
}

static int smb_recv_exact(SOCKET socket_handle, uint8_t *data, size_t length)
{
    size_t received_total = 0;

    while (received_total < length) {
        size_t remaining = length - received_total;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int received = recv(socket_handle, (char *)data + received_total, chunk, 0);

        if (received == SOCKET_ERROR || received == 0)
            return -1;

        received_total += (size_t)received;
    }

    return 0;
}

static int smb_read_response(SOCKET socket_handle, uint8_t **response, size_t *response_length)
{
    uint8_t header[4];
    uint32_t body_length;
    uint8_t *buffer;

    *response = NULL;
    *response_length = 0;

    if (smb_recv_exact(socket_handle, header, sizeof(header)) != 0)
        return -1;

    body_length = ((uint32_t)header[1] << 16) |
                  ((uint32_t)header[2] << 8) |
                  (uint32_t)header[3];

    buffer = (uint8_t *)malloc((size_t)body_length + sizeof(header));
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (body_length != 0 &&
        smb_recv_exact(socket_handle, buffer + sizeof(header), body_length) != 0) {
        free(buffer);
        return -1;
    }

    *response = buffer;
    *response_length = (size_t)body_length + sizeof(header);
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
    uint8_t user_id[2];
    uint8_t tree_id[2];
    uint32_t nt_status;
    SOCKET socket_handle;
    int result = -1;

    if (ip == NULL)
        return -1;

    socket_handle = smb_connect(ip, port);
    if (socket_handle == INVALID_SOCKET)
        return -1;

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(negotiate_packet));
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(session_setup_packet));
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(tree_connect_packet));
    memcpy(trans_named_pipe_packet, SMB_TRANS_NAMED_PIPE_PKT,
           sizeof(trans_named_pipe_packet));

    if (smb_send_all(socket_handle, negotiate_packet,
                     sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        smb_read_response(socket_handle, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (smb_send_all(socket_handle, session_setup_packet,
                     sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        smb_read_response(socket_handle, &response, &response_length) != 0)
        goto cleanup;

    if (response_length < 34)
        goto cleanup;

    user_id[0] = response[32];
    user_id[1] = response[33];
    free(response);
    response = NULL;

    session_setup_packet[32] = user_id[0];
    session_setup_packet[33] = user_id[1];
    tree_connect_packet[32] = user_id[0];
    tree_connect_packet[33] = user_id[1];

    if (smb_send_all(socket_handle, tree_connect_packet,
                     sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        smb_read_response(socket_handle, &response, &response_length) != 0)
        goto cleanup;

    if (response_length < 34)
        goto cleanup;

    tree_id[0] = response[28];
    tree_id[1] = response[29];
    free(response);
    response = NULL;

    trans_named_pipe_packet[28] = tree_id[0];
    trans_named_pipe_packet[29] = tree_id[1];
    trans_named_pipe_packet[32] = user_id[0];
    trans_named_pipe_packet[33] = user_id[1];

    if (smb_send_all(socket_handle, trans_named_pipe_packet,
                     sizeof(SMB_TRANS_NAMED_PIPE_PKT) - 1) != 0 ||
        smb_read_response(socket_handle, &response, &response_length) != 0)
        goto cleanup;

    if (response_length < (size_t)SMB_RESP_NT_STATUS_OFFSET + sizeof(uint32_t))
        goto cleanup;

    nt_status = (uint32_t)response[SMB_RESP_NT_STATUS_OFFSET] |
                ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 1] << 8) |
                ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 2] << 16) |
                ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 3] << 24);

    result = nt_status == (uint32_t)NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;

cleanup:
    free(response);
    closesocket(socket_handle);
    return result;
}