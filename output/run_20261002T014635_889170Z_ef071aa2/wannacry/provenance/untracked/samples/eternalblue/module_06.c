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
#include <sys/socket.h>
#include <unistd.h>

extern int smb_connect(const char *ip, int port);

static int doublepulsar_send_all(int fd, const unsigned char *buf, size_t len)
{
    size_t sent = 0;

    while (sent < len) {
        ssize_t n = send(fd, buf + sent, len - sent, MSG_NOSIGNAL);
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

static int doublepulsar_recv_all(int fd, unsigned char *buf, size_t len)
{
    size_t received = 0;

    while (received < len) {
        ssize_t n = recv(fd, buf + received, len - received, 0);
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

static int doublepulsar_read_response(int fd, unsigned char **response,
                                      size_t *response_len)
{
    unsigned char header[4];

    for (;;) {
        if (doublepulsar_recv_all(fd, header, sizeof(header)) < 0)
            return -1;

        size_t payload_len = ((size_t)header[1] << 16) |
                             ((size_t)header[2] << 8) |
                             (size_t)header[3];

        if (header[0] == 0x85)
            continue;
        if (header[0] != 0x00)
            return -1;

        unsigned char *buf = malloc(payload_len + sizeof(header));
        if (buf == NULL)
            return -1;

        for (size_t i = 0; i < sizeof(header); i++)
            buf[i] = header[i];

        if (doublepulsar_recv_all(fd, buf + sizeof(header), payload_len) < 0) {
            free(buf);
            return -1;
        }

        *response = buf;
        *response_len = payload_len + sizeof(header);
        return 0;
    }
}

int doublepulsar_check(const char *ip, int port)
{
    int fd = smb_connect(ip, port);
    unsigned char tc[sizeof(SMB_TREE_CONNECT_PKT)];
    unsigned char dp[sizeof(DP_PING_PKT)];
    unsigned char *response = NULL;
    size_t response_len = 0;
    unsigned char uid[2] = {0, 0};
    unsigned char tid[2] = {0, 0};
    int result = -1;

    if (fd < 0)
        return -1;

    if (doublepulsar_send_all(fd, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT) - 1) < 0)
        goto done;
    if (doublepulsar_read_response(fd, &response, &response_len) < 0)
        goto done;
    free(response);
    response = NULL;

    if (doublepulsar_send_all(fd, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT) - 1) < 0)
        goto done;
    if (doublepulsar_read_response(fd, &response, &response_len) < 0)
        goto done;
    if (response_len >= 34) {
        uid[0] = response[32];
        uid[1] = response[33];
    }
    free(response);
    response = NULL;

    memcpy(tc, SMB_TREE_CONNECT_PKT, sizeof(tc));
    tc[32] = uid[0];
    tc[33] = uid[1];
    if (doublepulsar_send_all(fd, tc, sizeof(tc) - 1) < 0)
        goto done;
    if (doublepulsar_read_response(fd, &response, &response_len) < 0)
        goto done;
    if (response_len >= 30) {
        tid[0] = response[28];
        tid[1] = response[29];
    }
    free(response);
    response = NULL;

    memcpy(dp, DP_PING_PKT, sizeof(dp));
    dp[28] = tid[0];
    dp[29] = tid[1];
    dp[32] = uid[0];
    dp[33] = uid[1];
    if (doublepulsar_send_all(fd, dp, sizeof(dp) - 1) < 0)
        goto done;
    if (doublepulsar_read_response(fd, &response, &response_len) < 0)
        goto done;

    if (response_len > (size_t)SMB_RESP_MUX_ID_OFFSET) {
        unsigned char mux_byte = response[SMB_RESP_MUX_ID_OFFSET];
        result = (mux_byte == DP_MULTIPLEX_ID_PING) ? 1 : 0;
    }
    free(response);
    response = NULL;

done:
    close(fd);
    return result;
}