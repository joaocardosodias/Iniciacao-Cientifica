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
#include "config.h"

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    HANDLE input_file = INVALID_HANDLE_VALUE;
    HANDLE temporary_file = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE symmetric_key = NULL;
    NTSTATUS status;
    LARGE_INTEGER file_size;
    unsigned char nonce[12];
    unsigned char *input_data = NULL;
    unsigned char *key_object = NULL;
    unsigned char *output_data = NULL;
    char *final_path = NULL;
    char *temporary_path = NULL;
    size_t path_length;
    size_t suffix_length;
    size_t output_size;
    size_t bytes_done;
    size_t remaining;
    ULONG input_length;
    ULONG key_object_length = 0;
    ULONG property_result_length = 0;
    ULONG encrypted_length = 0;
    DWORD bytes_read;
    DWORD bytes_written;
    BOOL temporary_created = FALSE;
    BOOL success = FALSE;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    path_length = strlen(path);
    suffix_length = strlen(ENCRYPTED_SUFFIX);
    if (path_length > SIZE_MAX - suffix_length ||
        path_length + suffix_length > SIZE_MAX - 5)
        return -1;

    final_path = (char *)malloc(path_length + suffix_length + 1);
    temporary_path = (char *)malloc(path_length + suffix_length + 5);
    if (final_path == NULL || temporary_path == NULL)
        goto cleanup;

    memcpy(final_path, path, path_length);
    memcpy(final_path + path_length, ENCRYPTED_SUFFIX, suffix_length + 1);
    memcpy(temporary_path, final_path, path_length + suffix_length);
    memcpy(temporary_path + path_length + suffix_length, ".tmp", 5);

    input_file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(input_file, &file_size) || file_size.QuadPart < 0 ||
        (ULONGLONG)file_size.QuadPart > (ULONGLONG)ULONG_MAX)
        goto cleanup;

    input_length = (ULONG)file_size.QuadPart;
    if ((size_t)input_length > SIZE_MAX - 29)
        goto cleanup;
    output_size = (size_t)input_length + 29;

    input_data = (unsigned char *)malloc(input_length == 0 ? 1 : (size_t)input_length);
    output_data = (unsigned char *)malloc(output_size);
    if (input_data == NULL || output_data == NULL)
        goto cleanup;

    bytes_done = 0;
    while (bytes_done < (size_t)input_length) {
        DWORD chunk = (DWORD)(((size_t)input_length - bytes_done) > MAXDWORD
                                  ? MAXDWORD
                                  : (size_t)input_length - bytes_done);
        if (!ReadFile(input_file, input_data + bytes_done, chunk, &bytes_read, NULL) ||
            bytes_read == 0)
            goto cleanup;
        bytes_done += bytes_read;
    }

    if (!CloseHandle(input_file))
        goto cleanup;
    input_file = INVALID_HANDLE_VALUE;

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
                               &property_result_length, 0);
    if (status < 0 || key_object_length == 0)
        goto cleanup;

    key_object = (unsigned char *)malloc(key_object_length);
    if (key_object == NULL)
        goto cleanup;

    status = BCryptGenerateSymmetricKey(algorithm, &symmetric_key, key_object,
                                        key_object_length, (PUCHAR)key,
                                        (ULONG)key_len, 0);
    if (status < 0)
        goto cleanup;

    status = BCryptGenRandom(NULL, nonce, (ULONG)sizeof(nonce),
                             BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (status < 0)
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

        status = BCryptEncrypt(symmetric_key, input_data, input_length,
                               &auth_info, NULL, 0, output_data + 13,
                               input_length, &encrypted_length, 0);
        if (status < 0 || encrypted_length != input_length)
            goto cleanup;
    }

    if (symmetric_key != NULL) {
        BCryptDestroyKey(symmetric_key);
        symmetric_key = NULL;
    }
    if (algorithm != NULL) {
        BCryptCloseAlgorithmProvider(algorithm, 0);
        algorithm = NULL;
    }

    temporary_file = CreateFileA(temporary_path, GENERIC_WRITE, 0, NULL,
                                 CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (temporary_file == INVALID_HANDLE_VALUE)
        goto cleanup;
    temporary_created = TRUE;

    bytes_done = 0;
    remaining = output_size;
    while (remaining != 0) {
        DWORD chunk = (DWORD)(remaining > MAXDWORD ? MAXDWORD : remaining);
        if (!WriteFile(temporary_file, output_data + bytes_done, chunk,
                       &bytes_written, NULL) ||
            bytes_written == 0)
            goto cleanup;
        bytes_done += bytes_written;
        remaining -= bytes_written;
    }

    if (!FlushFileBuffers(temporary_file))
        goto cleanup;
    if (!CloseHandle(temporary_file))
        goto cleanup;
    temporary_file = INVALID_HANDLE_VALUE;

    if (!MoveFileExA(temporary_path, final_path, MOVEFILE_REPLACE_EXISTING))
        goto cleanup;

    temporary_created = FALSE;
    success = TRUE;

cleanup:
    if (input_file != INVALID_HANDLE_VALUE)
        CloseHandle(input_file);
    if (temporary_file != INVALID_HANDLE_VALUE)
        CloseHandle(temporary_file);
    if (symmetric_key != NULL)
        BCryptDestroyKey(symmetric_key);
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    if (temporary_created && temporary_path != NULL)
        DeleteFileA(temporary_path);
    free(input_data);
    free(key_object);
    free(output_data);
    free(final_path);
    free(temporary_path);

    return success ? 0 : -1;
}