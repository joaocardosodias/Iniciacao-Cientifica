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
#include "eternalblue_config.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <unistd.h>

extern int smb_connect(const char *ip, int port);

static int
ms17_send_all(int fd, const unsigned char *data, size_t length)
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

static int
ms17_recv_all(int fd, unsigned char *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        ssize_t n = recv(fd, data + received, length - received, 0);
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
ms17_send_exchange(int fd, const unsigned char *packet, size_t packet_length,
                   unsigned char **response, size_t *response_length)
{
    unsigned char header[4];
    unsigned char *buffer;
    size_t payload_length;

    *response = NULL;
    *response_length = 0;

    if (ms17_send_all(fd, packet, packet_length) < 0 ||
        ms17_recv_all(fd, header, sizeof(header)) < 0)
        return -1;

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];
    buffer = malloc(sizeof(header) + payload_length);
    if (buffer == NULL)
        return -1;

    for (size_t i = 0; i < sizeof(header); ++i)
        buffer[i] = header[i];

    if (ms17_recv_all(fd, buffer + sizeof(header), payload_length) < 0) {
        free(buffer);
        return -1;
    }

    *response = buffer;
    *response_length = sizeof(header) + payload_length;
    return 0;
}

int
ms17_vuln_status(const char *ip, int port)
{
    int fd;
    int result = -1;
    unsigned char *response = NULL;
    size_t response_length = 0;
    uint32_t status;

    fd = smb_connect(ip, port);
    if (fd < 0)
        return -1;

#ifdef SMB_NEGOTIATE_PKT_LEN
    if (ms17_send_exchange(fd, (const unsigned char *)SMB_NEGOTIATE_PKT,
                           SMB_NEGOTIATE_PKT_LEN, &response,
                           &response_length) < 0)
        goto cleanup;
#else
    if (ms17_send_exchange(fd, (const unsigned char *)SMB_NEGOTIATE_PKT,
                           sizeof(SMB_NEGOTIATE_PKT) - 1, &response,
                           &response_length) < 0)
        goto cleanup;
#endif
    free(response);
    response = NULL;

#ifdef SMB_SESSION_SETUP_PKT_LEN
    if (ms17_send_exchange(fd, (const unsigned char *)SMB_SESSION_SETUP_PKT,
                           SMB_SESSION_SETUP_PKT_LEN, &response,
                           &response_length) < 0)
        goto cleanup;
#else
    if (ms17_send_exchange(fd, (const unsigned char *)SMB_SESSION_SETUP_PKT,
                           sizeof(SMB_SESSION_SETUP_PKT) - 1, &response,
                           &response_length) < 0)
        goto cleanup;
#endif
    free(response);
    response = NULL;

#ifdef SMB_TREE_CONNECT_PKT_LEN
    if (ms17_send_exchange(fd, (const unsigned char *)SMB_TREE_CONNECT_PKT,
                           SMB_TREE_CONNECT_PKT_LEN, &response,
                           &response_length) < 0)
        goto cleanup;
#else
    if (ms17_send_exchange(fd, (const unsigned char *)SMB_TREE_CONNECT_PKT,
                           sizeof(SMB_TREE_CONNECT_PKT) - 1, &response,
                           &response_length) < 0)
        goto cleanup;
#endif
    free(response);
    response = NULL;

#ifdef SMB_TRANS_NAMED_PIPE_PKT_LEN
    if (ms17_send_exchange(fd, (const unsigned char *)SMB_TRANS_NAMED_PIPE_PKT,
                           SMB_TRANS_NAMED_PIPE_PKT_LEN, &response,
                           &response_length) < 0)
        goto cleanup;
#else
    if (ms17_send_exchange(fd, (const unsigned char *)SMB_TRANS_NAMED_PIPE_PKT,
                           sizeof(SMB_TRANS_NAMED_PIPE_PKT) - 1, &response,
                           &response_length) < 0)
        goto cleanup;
#endif

    if (response_length < (size_t)SMB_RESP_NT_STATUS_OFFSET + 4)
        goto cleanup;

    status = (uint32_t)response[SMB_RESP_NT_STATUS_OFFSET] |
             ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 1] << 8) |
             ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 2] << 16) |
             ((uint32_t)response[SMB_RESP_NT_STATUS_OFFSET + 3] << 24);
    result = status == (uint32_t)NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;

cleanup:
    free(response);
    close(fd);
    return result;
}