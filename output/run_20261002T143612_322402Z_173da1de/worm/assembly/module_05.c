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
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    HANDLE input_file = INVALID_HANDLE_VALUE;
    HANDLE output_file = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE symmetric_key = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *output = NULL;
    unsigned char *key_object = NULL;
    char *final_path = NULL;
    char *temporary_path = NULL;
    size_t path_length;
    size_t suffix_length;
    size_t final_length;
    size_t plaintext_length = 0;
    size_t output_length;
    size_t offset;
    LARGE_INTEGER file_size;
    ULONG key_object_length = 0;
    ULONG property_result = 0;
    ULONG encrypted_length = 0;
    NTSTATUS status;
    int result = -1;

    if (path == NULL || key == NULL || key_len != 32)
        goto cleanup;

    path_length = strlen(path);
    suffix_length = strlen(ENCRYPTED_SUFFIX);
    if (path_length > SIZE_MAX - suffix_length)
        goto cleanup;
    final_length = path_length + suffix_length;
    if (final_length > SIZE_MAX - 5)
        goto cleanup;

    final_path = (char *)malloc(final_length + 1);
    temporary_path = (char *)malloc(final_length + 5);
    if (final_path == NULL || temporary_path == NULL)
        goto cleanup;

    memcpy(final_path, path, path_length);
    memcpy(final_path + path_length, ENCRYPTED_SUFFIX, suffix_length);
    final_path[final_length] = '\0';

    memcpy(temporary_path, final_path, final_length);
    memcpy(temporary_path + final_length, ".tmp", 5);

    input_file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(input_file, &file_size) || file_size.QuadPart < 0 ||
        (ULONGLONG)file_size.QuadPart > (ULONGLONG)SIZE_MAX ||
        (ULONGLONG)file_size.QuadPart > (ULONGLONG)(ULONG)-1)
        goto cleanup;

    plaintext_length = (size_t)file_size.QuadPart;
    plaintext = (unsigned char *)malloc(plaintext_length != 0 ? plaintext_length : 1);
    if (plaintext == NULL)
        goto cleanup;

    offset = 0;
    while (offset < plaintext_length) {
        size_t remaining = plaintext_length - offset;
        DWORD requested = remaining > (size_t)(DWORD)-1
                              ? (DWORD)-1
                              : (DWORD)remaining;
        DWORD bytes_read = 0;

        if (!ReadFile(input_file, plaintext + offset, requested, &bytes_read, NULL) ||
            bytes_read == 0)
            goto cleanup;
        offset += (size_t)bytes_read;
    }

    if (!CloseHandle(input_file)) {
        input_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    input_file = INVALID_HANDLE_VALUE;

    if (plaintext_length > SIZE_MAX - 29)
        goto cleanup;
    output_length = plaintext_length + 29;
    output = (unsigned char *)malloc(output_length);
    if (output == NULL)
        goto cleanup;

    output[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;

    status = BCryptGenRandom(NULL, output + 1, 12, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0)
        goto cleanup;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (status < 0)
        goto cleanup;

    status = BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (status < 0)
        goto cleanup;

    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                               (PUCHAR)&key_object_length,
                               (ULONG)sizeof(key_object_length),
                               &property_result, 0);
    if (status < 0 || property_result != sizeof(key_object_length) ||
        key_object_length == 0)
        goto cleanup;

    key_object = (unsigned char *)malloc((size_t)key_object_length);
    if (key_object == NULL)
        goto cleanup;

    status = BCryptGenerateSymmetricKey(algorithm, &symmetric_key, key_object,
                                        key_object_length, (PUCHAR)key,
                                        (ULONG)key_len, 0);
    if (status < 0)
        goto cleanup;

    {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;

        BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
        auth_info.pbNonce = output + 1;
        auth_info.cbNonce = 12;
        auth_info.pbTag = output + 13 + plaintext_length;
        auth_info.cbTag = 16;

        status = BCryptEncrypt(symmetric_key, plaintext, (ULONG)plaintext_length,
                               &auth_info, NULL, 0, output + 13,
                               (ULONG)plaintext_length, &encrypted_length, 0);
        if (status < 0 || encrypted_length != (ULONG)plaintext_length)
            goto cleanup;
    }

    output_file = CreateFileA(temporary_path, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (output_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    offset = 0;
    while (offset < output_length) {
        size_t remaining = output_length - offset;
        DWORD requested = remaining > (size_t)(DWORD)-1
                              ? (DWORD)-1
                              : (DWORD)remaining;
        DWORD bytes_written = 0;

        if (!WriteFile(output_file, output + offset, requested, &bytes_written, NULL) ||
            bytes_written == 0)
            goto cleanup;
        offset += (size_t)bytes_written;
    }

    if (!FlushFileBuffers(output_file))
        goto cleanup;
    if (!CloseHandle(output_file)) {
        output_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    output_file = INVALID_HANDLE_VALUE;

    if (!MoveFileExA(temporary_path, final_path, MOVEFILE_REPLACE_EXISTING))
        goto cleanup;

    result = 0;

cleanup:
    if (input_file != INVALID_HANDLE_VALUE)
        CloseHandle(input_file);
    if (output_file != INVALID_HANDLE_VALUE)
        CloseHandle(output_file);
    if (result != 0 && temporary_path != NULL)
        DeleteFileA(temporary_path);
    if (symmetric_key != NULL)
        BCryptDestroyKey(symmetric_key);
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    free(key_object);
    free(output);
    free(plaintext);
    free(temporary_path);
    free(final_path);
    return result;
}