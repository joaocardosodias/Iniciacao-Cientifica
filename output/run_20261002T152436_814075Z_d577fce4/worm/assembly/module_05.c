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
#include <windows.h>
#include <bcrypt.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    HANDLE input_file = INVALID_HANDLE_VALUE;
    HANDLE temp_file = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE symmetric_key = NULL;
    unsigned char *input_data = NULL;
    unsigned char *key_object = NULL;
    unsigned char *output_data = NULL;
    char *final_path = NULL;
    char *temp_path = NULL;
    unsigned char nonce[12];
    LARGE_INTEGER file_size;
    ULONG object_length = 0;
    ULONG result_length = 0;
    ULONG bytes_returned = 0;
    size_t input_length = 0;
    size_t output_length = 0;
    size_t path_length;
    size_t suffix_length;
    size_t final_length;
    size_t temp_length;
    size_t offset;
    DWORD bytes_read;
    DWORD bytes_written;
    int temp_created = 0;
    int status = -1;

    if (path == NULL || key == NULL || key_len != 32)
        goto cleanup;

    path_length = strlen(path);
    suffix_length = strlen(ENCRYPTED_SUFFIX);
    if (path_length > SIZE_MAX - suffix_length)
        goto cleanup;
    final_length = path_length + suffix_length;
    if (final_length > SIZE_MAX - 5)
        goto cleanup;
    temp_length = final_length + 4;

    final_path = (char *)malloc(final_length + 1);
    temp_path = (char *)malloc(temp_length + 1);
    if (final_path == NULL || temp_path == NULL)
        goto cleanup;

    memcpy(final_path, path, path_length);
    memcpy(final_path + path_length, ENCRYPTED_SUFFIX, suffix_length + 1);
    memcpy(temp_path, final_path, final_length);
    memcpy(temp_path + final_length, ".tmp", 5);

    input_file = CreateFileA(path, GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(input_file, &file_size) || file_size.QuadPart < 0)
        goto cleanup;
    if ((uint64_t)file_size.QuadPart > (uint64_t)ULONG_MAX)
        goto cleanup;
    input_length = (size_t)file_size.QuadPart;
    if (input_length > SIZE_MAX - 29)
        goto cleanup;
    output_length = input_length + 29;

    input_data = (unsigned char *)malloc(input_length != 0 ? input_length : 1);
    output_data = (unsigned char *)malloc(output_length);
    if (input_data == NULL || output_data == NULL)
        goto cleanup;

    offset = 0;
    while (offset < input_length) {
        DWORD request = (DWORD)((input_length - offset) > MAXDWORD
                                    ? MAXDWORD
                                    : (input_length - offset));
        if (!ReadFile(input_file, input_data + offset, request, &bytes_read, NULL) ||
            bytes_read == 0)
            goto cleanup;
        offset += bytes_read;
    }
    if (!CloseHandle(input_file))
        goto cleanup;
    input_file = INVALID_HANDLE_VALUE;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM,
                                                     NULL, 0)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                          (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                                          (PUCHAR)&object_length,
                                          (ULONG)sizeof(object_length),
                                          &bytes_returned, 0)) ||
        object_length == 0)
        goto cleanup;

    key_object = (unsigned char *)malloc(object_length);
    if (key_object == NULL)
        goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(algorithm, &symmetric_key,
                                                    key_object, object_length,
                                                    (PUCHAR)key, (ULONG)key_len, 0)))
        goto cleanup;
    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, nonce, (ULONG)sizeof(nonce),
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        goto cleanup;

    output_data[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    memcpy(output_data + 1, nonce, sizeof(nonce));

    {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
        BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
        auth_info.pbNonce = nonce;
        auth_info.cbNonce = (ULONG)sizeof(nonce);
        auth_info.pbTag = output_data + 13 + input_length;
        auth_info.cbTag = 16;

        if (!BCRYPT_SUCCESS(BCryptEncrypt(symmetric_key,
                                          input_data, (ULONG)input_length,
                                          &auth_info,
                                          NULL, 0,
                                          output_data + 13, (ULONG)input_length,
                                          &result_length, 0)) ||
            result_length != (ULONG)input_length)
            goto cleanup;
    }

    temp_file = CreateFileA(temp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (temp_file == INVALID_HANDLE_VALUE)
        goto cleanup;
    temp_created = 1;

    offset = 0;
    while (offset < output_length) {
        DWORD request = (DWORD)((output_length - offset) > MAXDWORD
                                    ? MAXDWORD
                                    : (output_length - offset));
        if (!WriteFile(temp_file, output_data + offset, request, &bytes_written, NULL) ||
            bytes_written == 0)
            goto cleanup;
        offset += bytes_written;
    }
    if (!FlushFileBuffers(temp_file))
        goto cleanup;
    if (!CloseHandle(temp_file))
        goto cleanup;
    temp_file = INVALID_HANDLE_VALUE;

    if (!MoveFileExA(temp_path, final_path, MOVEFILE_REPLACE_EXISTING))
        goto cleanup;

    temp_created = 0;
    status = 0;

cleanup:
    if (input_file != INVALID_HANDLE_VALUE)
        CloseHandle(input_file);
    if (temp_file != INVALID_HANDLE_VALUE)
        CloseHandle(temp_file);
    if (temp_created && temp_path != NULL)
        DeleteFileA(temp_path);
    if (symmetric_key != NULL)
        BCryptDestroyKey(symmetric_key);
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    free(input_data);
    free(key_object);
    free(output_data);
    free(final_path);
    free(temp_path);
    return status;
}