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
#include <unistd.h>

extern int smb_connect(const char *ip, int port);

static int
smb_send_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *p = buffer;

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
smb_recv_all(int fd, void *buffer, size_t length)
{
    unsigned char *p = buffer;

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
smb_read_response(int fd, unsigned char **response, size_t *response_length)
{
    unsigned char header[4];
    size_t body_length;
    unsigned char *buffer;

    if (smb_recv_all(fd, header, sizeof(header)) < 0)
        return -1;

    body_length = ((size_t)header[1] << 16) |
                  ((size_t)header[2] << 8) |
                  (size_t)header[3];

    buffer = malloc(sizeof(header) + body_length);
    if (buffer == NULL)
        return -1;

    for (size_t i = 0; i < sizeof(header); i++)
        buffer[i] = header[i];

    if (smb_recv_all(fd, buffer + sizeof(header), body_length) < 0) {
        free(buffer);
        return -1;
    }

    *response = buffer;
    *response_length = sizeof(header) + body_length;
    return 0;
}

int
ms17_vuln_status(const char *ip, int port)
{
    const unsigned char *packets[] = {
        SMB_NEGOTIATE_PKT,
        SMB_SESSION_SETUP_PKT,
        SMB_TREE_CONNECT_PKT,
        SMB_TRANS_NAMED_PIPE_PKT
    };
    const size_t packet_lengths[] = {
        sizeof(SMB_NEGOTIATE_PKT),
        sizeof(SMB_SESSION_SETUP_PKT),
        sizeof(SMB_TREE_CONNECT_PKT),
        sizeof(SMB_TRANS_NAMED_PIPE_PKT)
    };
    int fd = smb_connect(ip, port);
    int result = -1;

    if (fd < 0)
        return -1;

    for (size_t i = 0; i < sizeof(packets) / sizeof(packets[0]); i++) {
        unsigned char *response = NULL;
        size_t response_length = 0;

        if (smb_send_all(fd, packets[i], packet_lengths[i]) < 0)
            goto out;
        if (smb_read_response(fd, &response, &response_length) < 0)
            goto out;

        if (i == 3) {
            size_t status_offset = (size_t)SMB_RESP_NT_STATUS_OFFSET;

            if (status_offset <= response_length &&
                response_length - status_offset >= 4) {
                uint32_t status = (uint32_t)response[status_offset] |
                                  ((uint32_t)response[status_offset + 1] << 8) |
                                  ((uint32_t)response[status_offset + 2] << 16) |
                                  ((uint32_t)response[status_offset + 3] << 24);
                result = status == (uint32_t)NT_STATUS_INSUFF_SERVER_RESOURCES
                             ? 1
                             : 0;
            }
        }

        free(response);
        if (result != -1)
            break;
    }

out:
    close(fd);
    return result;
}