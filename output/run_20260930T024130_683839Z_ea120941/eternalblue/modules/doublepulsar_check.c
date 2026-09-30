#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

extern int smb_connect(const char *ip, int port);

static int
doublepulsar_send_all(int fd, const unsigned char *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        ssize_t n = send(fd, data + sent, length - sent, MSG_NOSIGNAL);
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
doublepulsar_recv_exact(int fd, unsigned char *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        ssize_t n = recv(fd, data + received, length - received, 0);
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
doublepulsar_exchange(int fd, const unsigned char *packet, size_t packet_length,
                      unsigned char **response, size_t *response_length)
{
    unsigned char header[4];
    size_t payload_length;
    unsigned char *frame;

    if (doublepulsar_send_all(fd, packet, packet_length) < 0)
        return -1;
    if (doublepulsar_recv_exact(fd, header, sizeof(header)) < 0)
        return -1;

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];
    frame = malloc(sizeof(header) + payload_length);
    if (frame == NULL)
        return -1;

    for (size_t i = 0; i < sizeof(header); ++i)
        frame[i] = header[i];
    if (doublepulsar_recv_exact(fd, frame + sizeof(header), payload_length) < 0) {
        free(frame);
        return -1;
    }

    *response = frame;
    *response_length = sizeof(header) + payload_length;
    return 0;
}

int
doublepulsar_check(const char *ip, int port)
{
    int fd;
    unsigned char *response = NULL;
    size_t response_length = 0;
    uint16_t multiplex_id;

    fd = smb_connect(ip, port);
    if (fd < 0)
        return -1;

    if (doublepulsar_exchange(fd, (const unsigned char *)SMB_NEGOTIATE_PKT,
                              sizeof(SMB_NEGOTIATE_PKT), &response,
                              &response_length) < 0)
        goto error;
    free(response);
    response = NULL;

    if (doublepulsar_exchange(fd, (const unsigned char *)SMB_SESSION_SETUP_PKT,
                              sizeof(SMB_SESSION_SETUP_PKT), &response,
                              &response_length) < 0)
        goto error;
    free(response);
    response = NULL;

    if (doublepulsar_exchange(fd, (const unsigned char *)SMB_TREE_CONNECT_PKT,
                              sizeof(SMB_TREE_CONNECT_PKT), &response,
                              &response_length) < 0)
        goto error;
    free(response);
    response = NULL;

    if (doublepulsar_exchange(fd, (const unsigned char *)DP_PING_PKT,
                              sizeof(DP_PING_PKT), &response,
                              &response_length) < 0)
        goto error;

    if (response_length < (size_t)SMB_RESP_MUX_ID_OFFSET + 2)
        goto error;

    multiplex_id = (uint16_t)response[SMB_RESP_MUX_ID_OFFSET] |
                   ((uint16_t)response[SMB_RESP_MUX_ID_OFFSET + 1] << 8);

    free(response);
    close(fd);
    return multiplex_id == DP_MULTIPLEX_ID_PING ? 1 : 0;

error:
    free(response);
    close(fd);
    return -1;
}