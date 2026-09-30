#define _GNU_SOURCE
#include "doublepulsar.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int dp_send_all(int fd, const void *data, size_t length)
{
    const unsigned char *p = data;

    while (length > 0) {
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

static int dp_read_all(int fd, void *data, size_t length)
{
    unsigned char *p = data;

    while (length > 0) {
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

static int dp_send_packet(int fd, const void *packet)
{
    const unsigned char *p = packet;
    size_t length = 4U + ((size_t)p[1] << 16) +
                    ((size_t)p[2] << 8) + (size_t)p[3];

    return dp_send_all(fd, packet, length);
}

static int dp_read_frame(int fd, unsigned char **frame, size_t *frame_length)
{
    unsigned char header[4];
    size_t payload_length;
    unsigned char *buffer;

    if (dp_read_all(fd, header, sizeof(header)) < 0)
        return -1;

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];

    buffer = malloc(sizeof(header) + payload_length);
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (payload_length > 0 &&
        dp_read_all(fd, buffer + sizeof(header), payload_length) < 0) {
        free(buffer);
        return -1;
    }

    *frame = buffer;
    *frame_length = sizeof(header) + payload_length;
    return 0;
}

int doublepulsar_check(const char *ip, int port)
{
    int fd;
    int result = -1;
    const void *packets[] = {
        SMB_NEGOTIATE_PKT,
        SMB_SESSION_SETUP_PKT,
        SMB_TREE_CONNECT_PKT,
        DP_PING_PKT
    };

    fd = smb_connect(ip, port);
    if (fd < 0)
        return -1;

    for (size_t i = 0; i < sizeof(packets) / sizeof(packets[0]); i++) {
        unsigned char *response = NULL;
        size_t response_length = 0;

        if (dp_send_packet(fd, packets[i]) < 0)
            goto done;

        if (dp_read_frame(fd, &response, &response_length) < 0)
            goto done;

        if (i == sizeof(packets) / sizeof(packets[0]) - 1) {
            if (response_length >= SMB_RESP_MUX_ID_OFFSET + 2) {
                uint16_t multiplex_id =
                    (uint16_t)response[SMB_RESP_MUX_ID_OFFSET] |
                    ((uint16_t)response[SMB_RESP_MUX_ID_OFFSET + 1] << 8);
                result = multiplex_id == DP_MULTIPLEX_ID_PING ? 1 : 0;
            }
            free(response);
            goto done;
        }

        free(response);
    }

done:
    close(fd);
    return result;
}