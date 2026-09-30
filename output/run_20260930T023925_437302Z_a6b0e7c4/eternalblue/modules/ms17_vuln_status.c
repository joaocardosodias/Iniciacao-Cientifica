#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

extern int smb_connect(const char *ip, int port);

static int
send_all(int fd, const unsigned char *data, size_t len)
{
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, data + sent, len - sent, MSG_NOSIGNAL);
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
recv_all(int fd, unsigned char *data, size_t len)
{
    size_t received = 0;

    while (received < len) {
        ssize_t n = recv(fd, data + received, len - received, 0);
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
read_smb_response(int fd, unsigned char **response, size_t *response_len)
{
    unsigned char header[4];
    size_t payload_len;
    unsigned char *buf;

    if (recv_all(fd, header, sizeof(header)) < 0)
        return -1;

    payload_len = ((size_t)header[1] << 16) |
                  ((size_t)header[2] << 8) |
                  (size_t)header[3];
    buf = malloc(sizeof(header) + payload_len);
    if (buf == NULL)
        return -1;

    for (size_t i = 0; i < sizeof(header); i++)
        buf[i] = header[i];

    if (payload_len != 0 &&
        recv_all(fd, buf + sizeof(header), payload_len) < 0) {
        free(buf);
        return -1;
    }

    *response = buf;
    *response_len = sizeof(header) + payload_len;
    return 0;
}

static int
send_packet_and_read_response(int fd, const unsigned char *packet)
{
    size_t packet_len = 4 + ((size_t)packet[1] << 16) |
                        ((size_t)packet[2] << 8) |
                        (size_t)packet[3];
    unsigned char *response;
    size_t response_len;
    int result;

    if (send_all(fd, packet, packet_len) < 0)
        return -1;

    result = read_smb_response(fd, &response, &response_len);
    if (result < 0)
        return -1;

    free(response);
    return 0;
}

int
ms17_vuln_status(const char *ip, int port)
{
    int fd = smb_connect(ip, port);
    const unsigned char *packets[] = {
        (const unsigned char *)SMB_NEGOTIATE_PKT,
        (const unsigned char *)SMB_SESSION_SETUP_PKT,
        (const unsigned char *)SMB_TREE_CONNECT_PKT,
        (const unsigned char *)SMB_TRANS_NAMED_PIPE_PKT
    };
    unsigned char *response = NULL;
    size_t response_len = 0;
    uint32_t status;
    int result = -1;

    if (fd < 0)
        return -1;

    for (size_t i = 0; i < sizeof(packets) / sizeof(packets[0]); i++) {
        size_t packet_len = 4 + (((size_t)packets[i][1] << 16) |
                                 ((size_t)packets[i][2] << 8) |
                                 (size_t)packets[i][3]);

        if (send_all(fd, packets[i], packet_len) < 0)
            goto out;

        if (read_smb_response(fd, &response, &response_len) < 0)
            goto out;

        if (i + 1 < sizeof(packets) / sizeof(packets[0])) {
            free(response);
            response = NULL;
            response_len = 0;
        }
    }

    if ((size_t)SMB_RESP_NT_STATUS_OFFSET + 4 > response_len)
        goto out;

    status = (uint32_t)response[SMB_RESP_NT_STATUS_OFFSET] |
             ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 1] << 8) |
             ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 2] << 16) |
             ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 3] << 24);
    result = status == (uint32_t)NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;

out:
    free(response);
    close(fd);
    return result;
}