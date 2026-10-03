#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include <limits.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

int ms17_vuln_status(const char *ip, int port)
{
    unsigned char negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    unsigned char session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    unsigned char tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    unsigned char trans_named_pipe_packet[sizeof(SMB_TRANS_NAMED_PIPE_PKT)];
    unsigned char *packets[4];
    size_t packet_lengths[4];
    unsigned char response[256];
    unsigned char netbios_header[4];
    unsigned char discard[1024];
    size_t status_offset = (size_t)SMB_RESP_NT_STATUS_OFFSET;
    size_t required_bytes;
    SOCKET sock;
    int result = -1;
    size_t i;

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    memcpy(trans_named_pipe_packet, SMB_TRANS_NAMED_PIPE_PKT, sizeof(SMB_TRANS_NAMED_PIPE_PKT));

    packets[0] = negotiate_packet;
    packets[1] = session_setup_packet;
    packets[2] = tree_connect_packet;
    packets[3] = trans_named_pipe_packet;

    packet_lengths[0] = sizeof(SMB_NEGOTIATE_PKT) - 1;
    packet_lengths[1] = sizeof(SMB_SESSION_SETUP_PKT) - 1;
    packet_lengths[2] = sizeof(SMB_TREE_CONNECT_PKT) - 1;
    packet_lengths[3] = sizeof(SMB_TRANS_NAMED_PIPE_PKT) - 1;

    if (status_offset > sizeof(response) - 4)
        return -1;
    required_bytes = status_offset + 4;
    if (required_bytes < 36)
        required_bytes = 36;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return -1;

    for (i = 0; i < 4; ++i) {
        size_t sent = 0;
        size_t received;
        size_t payload_length;
        size_t capture_length;
        size_t remaining;

        if (packet_lengths[i] > INT_MAX)
            goto cleanup;

        while (sent < packet_lengths[i]) {
            int n = send(sock, (const char *)packets[i] + sent,
                         (int)(packet_lengths[i] - sent), 0);
            if (n == SOCKET_ERROR || n == 0)
                goto cleanup;
            sent += (size_t)n;
        }

        received = 0;
        while (received < sizeof(netbios_header)) {
            int n = recv(sock, (char *)netbios_header + received,
                         (int)(sizeof(netbios_header) - received), 0);
            if (n == SOCKET_ERROR || n == 0)
                goto cleanup;
            received += (size_t)n;
        }

        payload_length = ((size_t)netbios_header[1] << 16) |
                         ((size_t)netbios_header[2] << 8) |
                         (size_t)netbios_header[3];
        if (payload_length + sizeof(netbios_header) < required_bytes)
            goto cleanup;

        memcpy(response, netbios_header, sizeof(netbios_header));
        capture_length = payload_length;
        if (capture_length > sizeof(response) - sizeof(netbios_header))
            capture_length = sizeof(response) - sizeof(netbios_header);

        received = 0;
        while (received < capture_length) {
            int n = recv(sock, (char *)response + sizeof(netbios_header) + received,
                         (int)(capture_length - received), 0);
            if (n == SOCKET_ERROR || n == 0)
                goto cleanup;
            received += (size_t)n;
        }

        remaining = payload_length - capture_length;
        while (remaining > 0) {
            size_t chunk = remaining;
            if (chunk > sizeof(discard))
                chunk = sizeof(discard);
            received = 0;
            while (received < chunk) {
                int n = recv(sock, (char *)discard + received,
                             (int)(chunk - received), 0);
                if (n == SOCKET_ERROR || n == 0)
                    goto cleanup;
                received += (size_t)n;
            }
            remaining -= chunk;
        }

        if (i == 1) {
            tree_connect_packet[32] = response[32];
            tree_connect_packet[33] = response[33];
        } else if (i == 2) {
            trans_named_pipe_packet[28] = response[28];
            trans_named_pipe_packet[29] = response[29];
            trans_named_pipe_packet[32] = response[32];
            trans_named_pipe_packet[33] = response[33];
        } else if (i == 3) {
            uint32_t status = (uint32_t)response[status_offset] |
                              ((uint32_t)response[status_offset + 1] << 8) |
                              ((uint32_t)response[status_offset + 2] << 16) |
                              ((uint32_t)response[status_offset + 3] << 24);
            result = status == (uint32_t)NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;
        }
    }

cleanup:
    closesocket(sock);
    return result;
}