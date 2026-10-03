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
    uint8_t *packets[4];
    size_t packet_lengths[4];
    uint8_t *response = NULL;
    const size_t response_capacity = 131075U;
    SOCKET sock = INVALID_SOCKET;
    size_t response_length = 0;
    int result = -1;

    memcpy(negotiate, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    memcpy(session_setup, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    memcpy(tree_connect, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    memcpy(trans_named_pipe, SMB_TRANS_NAMED_PIPE_PKT, sizeof(SMB_TRANS_NAMED_PIPE_PKT));

    packets[0] = negotiate;
    packets[1] = session_setup;
    packets[2] = tree_connect;
    packets[3] = trans_named_pipe;
    packet_lengths[0] = sizeof(SMB_NEGOTIATE_PKT) - 1U;
    packet_lengths[1] = sizeof(SMB_SESSION_SETUP_PKT) - 1U;
    packet_lengths[2] = sizeof(SMB_TREE_CONNECT_PKT) - 1U;
    packet_lengths[3] = sizeof(SMB_TRANS_NAMED_PIPE_PKT) - 1U;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        goto cleanup;

    response = (uint8_t *)malloc(response_capacity);
    if (response == NULL)
        goto cleanup;

    for (size_t packet_index = 0; packet_index < 4U; ++packet_index) {
        size_t sent = 0;

        while (sent < packet_lengths[packet_index]) {
            int chunk = (int)(packet_lengths[packet_index] - sent);
            int amount = send(sock, (const char *)packets[packet_index] + sent, chunk, 0);
            if (amount == SOCKET_ERROR || amount == 0)
                goto cleanup;
            sent += (size_t)amount;
        }

        size_t received = 0;
        while (received < 4U) {
            int amount = recv(sock, (char *)response + received, (int)(4U - received), 0);
            if (amount == SOCKET_ERROR || amount == 0)
                goto cleanup;
            received += (size_t)amount;
        }

        size_t payload_length = ((size_t)response[1] << 16) |
                                ((size_t)response[2] << 8) |
                                (size_t)response[3];
        if (payload_length > response_capacity - 4U)
            goto cleanup;

        received = 0;
        while (received < payload_length) {
            size_t remaining = payload_length - received;
            int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
            int amount = recv(sock, (char *)response + 4U + received, chunk, 0);
            if (amount == SOCKET_ERROR || amount == 0)
                goto cleanup;
            received += (size_t)amount;
        }
        response_length = payload_length + 4U;

        if (packet_index == 1U) {
            if (response_length < 34U)
                goto cleanup;
            tree_connect[32] = response[32];
            tree_connect[33] = response[33];
        } else if (packet_index == 2U) {
            if (response_length < 34U)
                goto cleanup;
            trans_named_pipe[28] = response[28];
            trans_named_pipe[29] = response[29];
            trans_named_pipe[32] = response[32];
            trans_named_pipe[33] = response[33];
        }
    }

    if (response_length < (size_t)SMB_RESP_NT_STATUS_OFFSET + 4U)
        goto cleanup;

    {
        uint32_t status = (uint32_t)response[SMB_RESP_NT_STATUS_OFFSET] |
                          ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 1U] << 8) |
                          ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 2U] << 16) |
                          ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 3U] << 24);
        result = status == (uint32_t)NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;
    }

cleanup:
    if (sock != INVALID_SOCKET)
        closesocket(sock);
    free(response);
    return result;
}