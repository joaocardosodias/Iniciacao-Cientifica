#define _GNU_SOURCE
#include "config.h"

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
ms17_recv_all(int fd, void *data, size_t length)
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
ms17_read_response(int fd, uint32_t *status)
{
    unsigned char header[4];
    unsigned char *response;
    size_t body_length;
    size_t response_length;
    uint32_t value;

    if (ms17_recv_all(fd, header, sizeof(header)) < 0)
        return -1;

    body_length = ((size_t)header[1] << 16) |
                  ((size_t)header[2] << 8) |
                  (size_t)header[3];
    response_length = sizeof(header) + body_length;
    if (response_length < (size_t)SMB_RESP_NT_STATUS_OFFSET + 4)
        return -1;

    response = malloc(response_length);
    if (response == NULL)
        return -1;

    for (size_t i = 0; i < sizeof(header); i++)
        response[i] = header[i];

    if (ms17_recv_all(fd, response + sizeof(header), body_length) < 0) {
        free(response);
        return -1;
    }

    value = (uint32_t)response[SMB_RESP_NT_STATUS_OFFSET] |
            ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 1] << 8) |
            ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 2] << 16) |
            ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 3] << 24);
    free(response);
    *status = value;
    return 0;
}

int
ms17_vuln_status(const char *ip, int port)
{
    int fd = smb_connect(ip, port);
    uint32_t status = 0;
    int result = -1;

    if (fd < 0)
        return -1;

    if (ms17_send_all(fd, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT)) < 0 ||
        ms17_read_response(fd, &status) < 0)
        goto out;

    if (ms17_send_all(fd, SMB_SESSION_SETUP_PKT,
                      sizeof(SMB_SESSION_SETUP_PKT)) < 0 ||
        ms17_read_response(fd, &status) < 0)
        goto out;

    if (ms17_send_all(fd, SMB_TREE_CONNECT_PKT,
                      sizeof(SMB_TREE_CONNECT_PKT)) < 0 ||
        ms17_read_response(fd, &status) < 0)
        goto out;

    if (ms17_send_all(fd, SMB_TRANS_NAMED_PIPE_PKT,
                      sizeof(SMB_TRANS_NAMED_PIPE_PKT)) < 0 ||
        ms17_read_response(fd, &status) < 0)
        goto out;

    result = status == (uint32_t)NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;

out:
    close(fd);
    return result;
}