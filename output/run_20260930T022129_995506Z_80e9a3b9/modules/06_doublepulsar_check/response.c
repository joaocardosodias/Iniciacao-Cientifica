#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static int
dp_send_all(int fd, const void *data, size_t length)
{
    const unsigned char *p = data;

    while (length != 0) {
        ssize_t n = send(fd, p, length, MSG_NOSIGNAL);
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
dp_recv_all(int fd, void *data, size_t length)
{
    unsigned char *p = data;

    while (length != 0) {
        ssize_t n = recv(fd, p, length, 0);
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
dp_read_frame(int fd, unsigned char **frame_out, size_t *length_out)
{
    unsigned char header[4];
    size_t body_length;
    unsigned char *frame;

    if (dp_recv_all(fd, header, sizeof(header)) < 0)
        return -1;

    body_length = ((size_t)header[1] << 16) |
                  ((size_t)header[2] << 8) |
                  (size_t)header[3];
    frame = malloc(sizeof(header) + body_length);
    if (frame == NULL)
        return -1;

    for (size_t i = 0; i < sizeof(header); ++i)
        frame[i] = header[i];

    if (body_length != 0 &&
        dp_recv_all(fd, frame + sizeof(header), body_length) < 0) {
        free(frame);
        return -1;
    }

    *frame_out = frame;
    *length_out = sizeof(header) + body_length;
    return 0;
}

static int
dp_exchange(int fd, const void *packet, size_t packet_length,
            unsigned char **response, size_t *response_length)
{
    if (dp_send_all(fd, packet, packet_length) < 0)
        return -1;
    return dp_read_frame(fd, response, response_length);
}

int
doublepulsar_check(const char *ip, int port)
{
    int fd;
    int result = -1;
    unsigned char *response = NULL;
    size_t response_length = 0;

    fd = smb_connect(ip, port);
    if (fd < 0)
        return -1;

    if (dp_exchange(fd, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT),
                    &response, &response_length) < 0)
        goto done;
    free(response);
    response = NULL;

    if (dp_exchange(fd, SMB_SESSION_SETUP_PKT,
                    sizeof(SMB_SESSION_SETUP_PKT),
                    &response, &response_length) < 0)
        goto done;
    free(response);
    response = NULL;

    if (dp_exchange(fd, SMB_TREE_CONNECT_PKT,
                    sizeof(SMB_TREE_CONNECT_PKT),
                    &response, &response_length) < 0)
        goto done;
    free(response);
    response = NULL;

    if (dp_exchange(fd, DP_PING_PKT, sizeof(DP_PING_PKT),
                    &response, &response_length) < 0)
        goto done;

    if ((size_t)SMB_RESP_MUX_ID_OFFSET + 1 >= response_length)
        goto done;

    if (((uint16_t)response[SMB_RESP_MUX_ID_OFFSET] |
         ((uint16_t)response[SMB_RESP_MUX_ID_OFFSET + 1] << 8)) ==
        DP_MULTIPLEX_ID_PING)
        result = 1;
    else
        result = 0;

done:
    free(response);
    close(fd);
    return result;
}