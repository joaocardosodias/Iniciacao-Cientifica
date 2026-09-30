#define _GNU_SOURCE
#include "eternalblue_config.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

extern int smb_connect(const char *ip, int port);

static int
ms17_send_all(int fd, const void *data, size_t length)
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

static int
ms17_recv_all(int fd, void *data, size_t length)
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

static int
ms17_read_response(int fd, uint32_t *status)
{
    unsigned char header[4];
    unsigned char *packet;
    size_t length;
    size_t total;
    uint32_t value;

    for (;;) {
        if (ms17_recv_all(fd, header, sizeof(header)) < 0)
            return -1;

        length = ((size_t)header[1] << 16) |
                 ((size_t)header[2] << 8) |
                 (size_t)header[3];

        if (header[0] == 0x85 && length == 0)
            continue;
        if (header[0] != 0)
            return -1;

        total = sizeof(header) + length;
        packet = malloc(total);
        if (packet == NULL)
            return -1;

        for (size_t i = 0; i < sizeof(header); ++i)
            packet[i] = header[i];

        if (ms17_recv_all(fd, packet + sizeof(header), length) < 0) {
            free(packet);
            return -1;
        }

        if (status != NULL) {
            if ((size_t)SMB_RESP_NT_STATUS_OFFSET + sizeof(uint32_t) > total) {
                free(packet);
                return -1;
            }

            const unsigned char *p = packet + SMB_RESP_NT_STATUS_OFFSET;
            value = (uint32_t)p[0] |
                    ((uint32_t)p[1] << 8) |
                    ((uint32_t)p[2] << 16) |
                    ((uint32_t)p[3] << 24);
            *status = value;
        }

        free(packet);
        return 0;
    }
}

int
ms17_vuln_status(const char *ip, int port)
{
    int fd;
    int result = -1;
    uint32_t status;

    fd = smb_connect(ip, port);
    if (fd < 0)
        return -1;

    if (ms17_send_all(fd, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT)) < 0 ||
        ms17_read_response(fd, NULL) < 0 ||
        ms17_send_all(fd, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT)) < 0 ||
        ms17_read_response(fd, NULL) < 0 ||
        ms17_send_all(fd, SMB_TREE_CONNECT_PKT, sizeof(SMB_TREE_CONNECT_PKT)) < 0 ||
        ms17_read_response(fd, NULL) < 0 ||
        ms17_send_all(fd, SMB_TRANS_NAMED_PIPE_PKT, sizeof(SMB_TRANS_NAMED_PIPE_PKT)) < 0 ||
        ms17_read_response(fd, &status) < 0)
        goto out;

    result = status == NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;

out:
    close(fd);
    return result;
}