#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

extern int smb_connect(const char *ip, int port);

static int
send_all(int fd, const unsigned char *buffer, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        ssize_t n = send(fd, buffer + sent, length - sent, MSG_NOSIGNAL);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        sent += (size_t)n;
    }

    return 0;
}

static int
recv_all(int fd, unsigned char *buffer, size_t length)
{
    size_t received = 0;

    while (received < length) {
        ssize_t n = recv(fd, buffer + received, length - received, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        received += (size_t)n;
    }

    return 0;
}

static int
send_packet_read_response(int fd, const unsigned char *packet, size_t packet_length,
                          unsigned char **response, size_t *response_length)
{
    unsigned char header[4];
    size_t body_length;
    unsigned char *frame;

    if (send_all(fd, packet, packet_length) < 0)
        return -1;
    if (recv_all(fd, header, sizeof(header)) < 0)
        return -1;

    body_length = ((size_t)header[1] << 16) |
                  ((size_t)header[2] << 8) |
                  (size_t)header[3];
    frame = malloc(sizeof(header) + body_length);
    if (frame == NULL)
        return -1;

    for (size_t i = 0; i < sizeof(header); i++)
        frame[i] = header[i];

    if (body_length != 0 &&
        recv_all(fd, frame + sizeof(header), body_length) < 0) {
        free(frame);
        return -1;
    }

    *response = frame;
    *response_length = sizeof(header) + body_length;
    return 0;
}

int
doublepulsar_check(const char *ip, int port)
{
    int fd;
    unsigned char *response = NULL;
    size_t response_length = 0;
    uint16_t multiplex_id;
    int result = -1;

    fd = smb_connect(ip, port);
    if (fd < 0)
        return -1;

    if (send_packet_read_response(fd, SMB_NEGOTIATE_PKT,
                                  sizeof(SMB_NEGOTIATE_PKT),
                                  &response, &response_length) < 0)
        goto out;
    free(response);
    response = NULL;

    if (send_packet_read_response(fd, SMB_SESSION_SETUP_PKT,
                                  sizeof(SMB_SESSION_SETUP_PKT),
                                  &response, &response_length) < 0)
        goto out;
    free(response);
    response = NULL;

    if (send_packet_read_response(fd, SMB_TREE_CONNECT_PKT,
                                  sizeof(SMB_TREE_CONNECT_PKT),
                                  &response, &response_length) < 0)
        goto out;
    free(response);
    response = NULL;

    if (send_packet_read_response(fd, DP_PING_PKT, sizeof(DP_PING_PKT),
                                  &response, &response_length) < 0)
        goto out;

    if ((size_t)SMB_RESP_MUX_ID_OFFSET + 1 >= response_length)
        goto out;

    multiplex_id = (uint16_t)response[SMB_RESP_MUX_ID_OFFSET] |
                   (uint16_t)((uint16_t)response[SMB_RESP_MUX_ID_OFFSET + 1] << 8);
    result = multiplex_id == DP_MULTIPLEX_ID_PING ? 1 : 0;

out:
    free(response);
    close(fd);
    return result;
}