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
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

extern int smb_connect(const char *ip, int port);

static int ms17_send_all(int fd, const void *buffer, size_t length)
{
    const unsigned char *p = buffer;

    while (length > 0) {
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

static int ms17_read_all(int fd, void *buffer, size_t length)
{
    unsigned char *p = buffer;

    while (length > 0) {
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

static int ms17_read_smb_response(int fd, unsigned char **response,
                                  size_t *response_length)
{
    unsigned char header[4];
    unsigned char *buffer;
    size_t payload_length;

    if (ms17_read_all(fd, header, sizeof(header)) < 0)
        return -1;

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];
    buffer = malloc(sizeof(header) + payload_length);
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (payload_length != 0 &&
        ms17_read_all(fd, buffer + sizeof(header), payload_length) < 0) {
        free(buffer);
        return -1;
    }

    *response = buffer;
    *response_length = sizeof(header) + payload_length;
    return 0;
}

int ms17_vuln_status(const char *ip, int port)
{
    int fd;
    int result = -1;
    const unsigned char *packets[] = {
        (const unsigned char *)SMB_NEGOTIATE_PKT,
        (const unsigned char *)SMB_SESSION_SETUP_PKT,
        (const unsigned char *)SMB_TREE_CONNECT_PKT,
        (const unsigned char *)SMB_TRANS_NAMED_PIPE_PKT
    };
    const size_t packet_lengths[] = {
        sizeof(SMB_NEGOTIATE_PKT),
        sizeof(SMB_SESSION_SETUP_PKT),
        sizeof(SMB_TREE_CONNECT_PKT),
        sizeof(SMB_TRANS_NAMED_PIPE_PKT)
    };

    fd = smb_connect(ip, port);
    if (fd < 0)
        return -1;

    for (size_t i = 0; i < sizeof(packet_lengths) / sizeof(packet_lengths[0]); i++) {
        unsigned char *response = NULL;
        size_t response_length = 0;

        if (ms17_send_all(fd, packets[i], packet_lengths[i]) < 0)
            goto done;
        if (ms17_read_smb_response(fd, &response, &response_length) < 0)
            goto done;

        if (i == sizeof(packet_lengths) / sizeof(packet_lengths[0]) - 1) {
            size_t offset = (size_t)SMB_RESP_NT_STATUS_OFFSET;
            if (offset > response_length || response_length - offset < 4) {
                free(response);
                goto done;
            }

            uint32_t status = (uint32_t)response[offset] |
                              ((uint32_t)response[offset + 1] << 8) |
                              ((uint32_t)response[offset + 2] << 16) |
                              ((uint32_t)response[offset + 3] << 24);
            result = status == NT_STATUS_INSUFF_SERVER_RESOURCES ? 1 : 0;
        }

        free(response);
    }

done:
    close(fd);
    return result;
}