#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

int ms17_vuln_status(const char *ip, int port)
{
    uint8_t negotiate[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t trans_named_pipe[sizeof(SMB_TRANS_NAMED_PIPE_PKT)];
    SOCKET sock = INVALID_SOCKET;
    uint8_t *response = NULL;
    size_t response_length;
    size_t sent;
    size_t received;
    size_t packet_length;
    uint32_t netbios_length;
    uint32_t nt_status;
    int io_result;
    int result = -1;

    if (ip == NULL) {
        return -1;
    }

    memcpy(negotiate, SMB_NEGOTIATE_PKT, sizeof(negotiate));
    memcpy(session_setup, SMB_SESSION_SETUP_PKT, sizeof(session_setup));
    memcpy(tree_connect, SMB_TREE_CONNECT_PKT, sizeof(tree_connect));
    memcpy(trans_named_pipe, SMB_TRANS_NAMED_PIPE_PKT, sizeof(trans_named_pipe));

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET) {
        return -1;
    }

    packet_length = sizeof(SMB_NEGOTIATE_PKT) - 1;
    sent = 0;
    while (sent < packet_length) {
        io_result = send(sock, (const char *)negotiate + sent,
                         (int)(packet_length - sent), 0);
        if (io_result == SOCKET_ERROR || io_result == 0) {
            goto cleanup;
        }
        sent += (size_t)io_result;
    }

    response = (uint8_t *)malloc(4);
    if (response == NULL) {
        goto cleanup;
    }
    received = 0;
    while (received < 4) {
        io_result = recv(sock, (char *)response + received, (int)(4 - received), 0);
        if (io_result == SOCKET_ERROR || io_result == 0) {
            goto cleanup;
        }
        received += (size_t)io_result;
    }
    netbios_length = ((uint32_t)response[1] << 16) |
                     ((uint32_t)response[2] << 8) |
                     (uint32_t)response[3];
    response_length = (size_t)netbios_length + 4;
    {
        uint8_t *resized = (uint8_t *)realloc(response, response_length);
        if (resized == NULL) {
            goto cleanup;
        }
        response = resized;
    }
    received = 4;
    while (received < response_length) {
        io_result = recv(sock, (char *)response + received,
                         (int)(response_length - received), 0);
        if (io_result == SOCKET_ERROR || io_result == 0) {
            goto cleanup;
        }
        received += (size_t)io_result;
    }
    free(response);
    response = NULL;

    packet_length = sizeof(SMB_SESSION_SETUP_PKT) - 1;
    sent = 0;
    while (sent < packet_length) {
        io_result = send(sock, (const char *)session_setup + sent,
                         (int)(packet_length - sent), 0);
        if (io_result == SOCKET_ERROR || io_result == 0) {
            goto cleanup;
        }
        sent += (size_t)io_result;
    }

    response = (uint8_t *)malloc(4);
    if (response == NULL) {
        goto cleanup;
    }
    received = 0;
    while (received < 4) {
        io_result = recv(sock, (char *)response + received, (int)(4 - received), 0);
        if (io_result == SOCKET_ERROR || io_result == 0) {
            goto cleanup;
        }
        received += (size_t)io_result;
    }
    netbios_length = ((uint32_t)response[1] << 16) |
                     ((uint32_t)response[2] << 8) |
                     (uint32_t)response[3];
    response_length = (size_t)netbios_length + 4;
    {
        uint8_t *resized = (uint8_t *)realloc(response, response_length);
        if (resized == NULL) {
            goto cleanup;
        }
        response = resized;
    }
    received = 4;
    while (received < response_length) {
        io_result = recv(sock, (char *)response + received,
                         (int)(response_length - received), 0);
        if (io_result == SOCKET_ERROR || io_result == 0) {
            goto cleanup;
        }
        received += (size_t)io_result;
    }
    if (response_length < 34) {
        goto cleanup;
    }
    tree_connect[32] = response[32];
    tree_connect[33] = response[33];
    free(response);
    response = NULL;

    packet_length = sizeof(SMB_TREE_CONNECT_PKT) - 1;
    sent = 0;
    while (sent < packet_length) {
        io_result = send(sock, (const char *)tree_connect + sent,
                         (int)(packet_length - sent), 0);
        if (io_result == SOCKET_ERROR || io_result == 0) {
            goto cleanup;
        }
        sent += (size_t)io_result;
    }

    response = (uint8_t *)malloc(4);
    if (response == NULL) {
        goto cleanup;
    }
    received = 0;
    while (received < 4) {
        io_result = recv(sock, (char *)response + received, (int)(4 - received), 0);
        if (io_result == SOCKET_ERROR || io_result == 0) {
            goto cleanup;
        }
        received += (size_t)io_result;
    }
    netbios_length = ((uint32_t)response[1] << 16) |
                     ((uint32_t)response[2] << 8) |
                     (uint32_t)response[3];
    response_length = (size_t)netbios_length + 4;
    {
        uint8_t *resized = (uint8_t *)realloc(response, response_length);
        if (resized == NULL) {
            goto cleanup;
        }
        response = resized;
    }
    received = 4;
    while (received < response_length) {
        io_result = recv(sock, (char *)response + received,
                         (int)(response_length - received), 0);
        if (io_result == SOCKET_ERROR || io_result == 0) {
            goto cleanup;
        }
        received += (size_t)io_result;
    }
    if (response_length < 34) {
        goto cleanup;
    }
    trans_named_pipe[28] = response[28];
    trans_named_pipe[29] = response[29];
    trans_named_pipe[32] = tree_connect[32];
    trans_named_pipe[33] = tree_connect[33];
    free(response);
    response = NULL;

    packet_length = sizeof(SMB_TRANS_NAMED_PIPE_PKT) - 1;
    sent = 0;
    while (sent < packet_length) {
        io_result = send(sock, (const char *)trans_named_pipe + sent,
                         (int)(packet_length - sent), 0);
        if (io_result == SOCKET_ERROR || io_result == 0) {
            goto cleanup;
        }
        sent += (size_t)io_result;
    }

    response = (uint8_t *)malloc(4);
    if (response == NULL) {
        goto cleanup;
    }
    received = 0;
    while (received < 4) {
        io_result = recv(sock, (char *)response + received, (int)(4 - received), 0);
        if (io_result == SOCKET_ERROR || io_result == 0) {
            goto cleanup;
        }
        received += (size_t)io_result;
    }
    netbios_length = ((uint32_t)response[1] << 16) |
                     ((uint32_t)response[2] << 8) |
                     (uint32_t)response[3];
    response_length = (size_t)netbios_length + 4;
    {
        uint8_t *resized = (uint8_t *)realloc(response, response_length);
        if (resized == NULL) {
            goto cleanup;
        }
        response = resized;
    }
    received = 4;
    while (received < response_length) {
        io_result = recv(sock, (char *)response + received,
                         (int)(response_length - received), 0);
        if (io_result == SOCKET_ERROR || io_result == 0) {
            goto cleanup;
        }
        received += (size_t)io_result;
    }

    if (response_length < (size_t)SMB_RESP_NT_STATUS_OFFSET + 4) {
        goto cleanup;
    }
    nt_status = (uint32_t)response[SMB_RESP_NT_STATUS_OFFSET] |
                ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 1] << 8) |
                ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 2] << 16) |
                ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 3] << 24);
    result = nt_status == (uint32_t)NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;

cleanup:
    free(response);
    closesocket(sock);
    return result;
}