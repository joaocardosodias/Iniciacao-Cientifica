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
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

int ms17_vuln_status(const char *ip, int port)
{
    uint8_t negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t trans_named_pipe_packet[sizeof(SMB_TRANS_NAMED_PIPE_PKT)];
    SOCKET sock = INVALID_SOCKET;
    uint8_t *response = NULL;
    int result = -1;

    if (ip == NULL)
        return -1;

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(negotiate_packet));
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(session_setup_packet));
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(tree_connect_packet));
    memcpy(trans_named_pipe_packet, SMB_TRANS_NAMED_PIPE_PKT, sizeof(trans_named_pipe_packet));

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return -1;

    for (int stage = 0; stage < 4; ++stage) {
        const uint8_t *packet;
        size_t packet_size;

        switch (stage) {
        case 0:
            packet = negotiate_packet;
            packet_size = sizeof(negotiate_packet) - 1;
            break;
        case 1:
            packet = session_setup_packet;
            packet_size = sizeof(session_setup_packet) - 1;
            break;
        case 2:
            packet = tree_connect_packet;
            packet_size = sizeof(tree_connect_packet) - 1;
            break;
        default:
            packet = trans_named_pipe_packet;
            packet_size = sizeof(trans_named_pipe_packet) - 1;
            break;
        }

        if (packet_size > INT_MAX)
            goto cleanup;

        size_t sent = 0;
        while (sent < packet_size) {
            int amount = (int)(packet_size - sent);
            int n = send(sock, (const char *)packet + sent, amount, 0);
            if (n == SOCKET_ERROR || n == 0)
                goto cleanup;
            sent += (size_t)n;
        }

        uint8_t header[4];
        size_t received = 0;
        while (received < sizeof(header)) {
            int n = recv(sock, (char *)header + received,
                         (int)(sizeof(header) - received), 0);
            if (n == SOCKET_ERROR || n == 0)
                goto cleanup;
            received += (size_t)n;
        }

        size_t body_size = ((size_t)header[1] << 16) |
                           ((size_t)header[2] << 8) |
                           (size_t)header[3];
        size_t frame_size = sizeof(header) + body_size;
        response = (uint8_t *)malloc(frame_size);
        if (response == NULL)
            goto cleanup;

        memcpy(response, header, sizeof(header));
        received = 0;
        while (received < body_size) {
            size_t remaining = body_size - received;
            int amount = remaining > INT_MAX ? INT_MAX : (int)remaining;
            int n = recv(sock, (char *)response + sizeof(header) + received,
                         amount, 0);
            if (n == SOCKET_ERROR || n == 0)
                goto cleanup;
            received += (size_t)n;
        }

        if (stage == 1) {
            if (frame_size < 34)
                goto cleanup;
            tree_connect_packet[32] = response[32];
            tree_connect_packet[33] = response[33];
        } else if (stage == 2) {
            if (frame_size < 34)
                goto cleanup;
            trans_named_pipe_packet[28] = response[28];
            trans_named_pipe_packet[29] = response[29];
            trans_named_pipe_packet[32] = response[32];
            trans_named_pipe_packet[33] = response[33];
        } else if (stage == 3) {
            size_t status_offset = (size_t)SMB_RESP_NT_STATUS_OFFSET;
            if (status_offset > frame_size || frame_size - status_offset < 4)
                goto cleanup;

            uint32_t status = (uint32_t)response[status_offset] |
                              ((uint32_t)response[status_offset + 1] << 8) |
                              ((uint32_t)response[status_offset + 2] << 16) |
                              ((uint32_t)response[status_offset + 3] << 24);
            result = status == (uint32_t)NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;
        }

        free(response);
        response = NULL;
    }

cleanup:
    free(response);
    if (sock != INVALID_SOCKET)
        closesocket(sock);
    return result;
}