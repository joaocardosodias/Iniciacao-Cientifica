#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int ms17_send_all(SOCKET sock, const unsigned char *data, size_t length)
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

static int ms17_recv_all(SOCKET sock, unsigned char *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)data + received, chunk, 0);

        if (result == SOCKET_ERROR || result == 0) {
            return -1;
        }
        received += (size_t)result;
    }

    return 0;
}

static int ms17_read_response(SOCKET sock, unsigned char *captured, size_t captured_capacity,
                              size_t *captured_length)
{
    unsigned char netbios_header[4];
    unsigned char buffer[4096];
    size_t remaining;
    size_t stored;

    if (ms17_recv_all(sock, netbios_header, sizeof(netbios_header)) != 0) {
        return -1;
    }

    remaining = ((size_t)netbios_header[1] << 16) |
                ((size_t)netbios_header[2] << 8) |
                (size_t)netbios_header[3];

    stored = sizeof(netbios_header);
    if (captured_capacity < stored) {
        return -1;
    }
    memcpy(captured, netbios_header, stored);

    while (remaining != 0) {
        size_t chunk = remaining < sizeof(buffer) ? remaining : sizeof(buffer);

        if (ms17_recv_all(sock, buffer, chunk) != 0) {
            return -1;
        }

        if (stored < captured_capacity) {
            size_t copy_length = captured_capacity - stored;
            if (copy_length > chunk) {
                copy_length = chunk;
            }
            memcpy(captured + stored, buffer, copy_length);
            stored += copy_length;
        }

        remaining -= chunk;
    }

    *captured_length = stored;
    return 0;
}

int ms17_vuln_status(const char *ip, int port)
{
    SOCKET sock;
    unsigned char *negotiate = NULL;
    unsigned char *session_setup = NULL;
    unsigned char *tree_connect = NULL;
    unsigned char *trans_named_pipe = NULL;
    unsigned char response[64];
    size_t response_length;
    size_t status_offset = (size_t)SMB_RESP_NT_STATUS_OFFSET;
    uint32_t status;
    int result = -1;

    if (ip == NULL || port < 1 || port > 65535) {
        return -1;
    }

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    negotiate = (unsigned char *)malloc(sizeof(SMB_NEGOTIATE_PKT));
    session_setup = (unsigned char *)malloc(sizeof(SMB_SESSION_SETUP_PKT));
    tree_connect = (unsigned char *)malloc(sizeof(SMB_TREE_CONNECT_PKT));
    trans_named_pipe = (unsigned char *)malloc(sizeof(SMB_TRANS_NAMED_PIPE_PKT));
    if (negotiate == NULL || session_setup == NULL || tree_connect == NULL ||
        trans_named_pipe == NULL) {
        goto cleanup;
    }

    memcpy(negotiate, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    memcpy(session_setup, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    memcpy(tree_connect, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    memcpy(trans_named_pipe, SMB_TRANS_NAMED_PIPE_PKT, sizeof(SMB_TRANS_NAMED_PIPE_PKT));

    if (ms17_send_all(sock, negotiate, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        ms17_read_response(sock, response, sizeof(response), &response_length) != 0) {
        goto cleanup;
    }

    if (ms17_send_all(sock, session_setup, sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        ms17_read_response(sock, response, sizeof(response), &response_length) != 0 ||
        response_length < 34) {
        goto cleanup;
    }

    session_setup[32] = response[32];
    session_setup[33] = response[33];
    tree_connect[32] = response[32];
    tree_connect[33] = response[33];

    if (ms17_send_all(sock, tree_connect, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        ms17_read_response(sock, response, sizeof(response), &response_length) != 0 ||
        response_length < 34) {
        goto cleanup;
    }

    trans_named_pipe[28] = response[28];
    trans_named_pipe[29] = response[29];
    trans_named_pipe[32] = session_setup[32];
    trans_named_pipe[33] = session_setup[33];

    if (ms17_send_all(sock, trans_named_pipe, sizeof(SMB_TRANS_NAMED_PIPE_PKT) - 1) != 0 ||
        ms17_read_response(sock, response, sizeof(response), &response_length) != 0 ||
        status_offset > response_length || response_length - status_offset < 4) {
        goto cleanup;
    }

    status = (uint32_t)response[status_offset] |
             ((uint32_t)response[status_offset + 1] << 8) |
             ((uint32_t)response[status_offset + 2] << 16) |
             ((uint32_t)response[status_offset + 3] << 24);

    result = status == (uint32_t)NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;

cleanup:
    free(negotiate);
    free(session_setup);
    free(tree_connect);
    free(trans_named_pipe);
    closesocket(sock);
    return result;
}