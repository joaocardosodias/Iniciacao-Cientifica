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
#include <limits.h>
#include "config.h"

int write_encrypted_sibling(const char *path, const unsigned char *key, size_t key_len)
{
    HANDLE input_file = INVALID_HANDLE_VALUE;
    HANDLE temp_file = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE symmetric_key = NULL;
    unsigned char *key_object = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *output = NULL;
    char *final_path = NULL;
    char *temp_path = NULL;
    unsigned char nonce[12];
    LARGE_INTEGER file_size;
    ULONG object_length = 0;
    ULONG property_result = 0;
    ULONG input_length = 0;
    ULONG encrypted_length = 0;
    size_t plaintext_size = 0;
    size_t suffix_length;
    size_t path_length;
    size_t final_length;
    size_t temp_length;
    size_t output_size;
    size_t offset;
    int temp_created = 0;
    int result = -1;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    path_length = strlen(path);
    suffix_length = strlen(ENCRYPTED_SUFFIX);
    if (suffix_length > SIZE_MAX - path_length - 1)
        goto cleanup;
    final_length = path_length + suffix_length;
    if (final_length > SIZE_MAX - sizeof(".tmp"))
        goto cleanup;
    temp_length = final_length + sizeof(".tmp") - 1;

    final_path = (char *)malloc(final_length + 1);
    temp_path = (char *)malloc(temp_length + 1);
    if (final_path == NULL || temp_path == NULL)
        goto cleanup;

    memcpy(final_path, path, path_length);
    memcpy(final_path + path_length, ENCRYPTED_SUFFIX, suffix_length);
    final_path[final_length] = '\0';
    memcpy(temp_path, final_path, final_length);
    memcpy(temp_path + final_length, ".tmp", sizeof(".tmp"));

    input_file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(input_file, &file_size) || file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > (uint64_t)ULONG_MAX)
        goto cleanup;

    plaintext_size = (size_t)file_size.QuadPart;
    input_length = (ULONG)plaintext_size;
    if (plaintext_size > SIZE_MAX - 29)
        goto cleanup;
    output_size = plaintext_size + 29;

    plaintext = (unsigned char *)malloc(plaintext_size != 0 ? plaintext_size : 1);
    output = (unsigned char *)malloc(output_size);
    if (plaintext == NULL || output == NULL)
        goto cleanup;

    offset = 0;
    while (offset < plaintext_size) {
        DWORD chunk = (DWORD)((plaintext_size - offset) > 1048576
                                  ? 1048576
                                  : (plaintext_size - offset));
        DWORD bytes_read = 0;
        if (!ReadFile(input_file, plaintext + offset, chunk, &bytes_read, NULL) ||
            bytes_read != chunk)
            goto cleanup;
        offset += bytes_read;
    }

    if (!CloseHandle(input_file)) {
        input_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    input_file = INVALID_HANDLE_VALUE;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(
            &algorithm, BCRYPT_AES_ALGORITHM, NULL, 0)))
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptSetProperty(
            algorithm, BCRYPT_CHAINING_MODE,
            (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
            (ULONG)sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptGetProperty(
            algorithm, BCRYPT_OBJECT_LENGTH, (PUCHAR)&object_length,
            (ULONG)sizeof(object_length), &property_result, 0)) ||
        property_result < sizeof(object_length) || object_length == 0)
        goto cleanup;

    key_object = (unsigned char *)malloc(object_length);
    if (key_object == NULL)
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(
            algorithm, &symmetric_key, key_object, object_length,
            (PUCHAR)key, (ULONG)key_len, 0)))
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptGenRandom(
            NULL, nonce, (ULONG)sizeof(nonce),
            BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        goto cleanup;

    output[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    memcpy(output + 1, nonce, sizeof(nonce));
    memset(output + 13 + plaintext_size, 0, 16);

    {
        BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
        unsigned char empty_input = 0;
        PUCHAR input_buffer = plaintext_size != 0 ? plaintext : &empty_input;

        BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
        auth_info.pbNonce = nonce;
        auth_info.cbNonce = (ULONG)sizeof(nonce);
        auth_info.pbTag = output + 13 + plaintext_size;
        auth_info.cbTag = 16;

        if (!BCRYPT_SUCCESS(BCryptEncrypt(
                symmetric_key, input_buffer, input_length, &auth_info,
                NULL, 0, output + 13, input_length, &encrypted_length, 0)) ||
            encrypted_length != input_length)
            goto cleanup;
    }

    temp_file = CreateFileA(temp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                            FILE_ATTRIBUTE_NORMAL, NULL);
    if (temp_file == INVALID_HANDLE_VALUE)
        goto cleanup;
    temp_created = 1;

    offset = 0;
    while (offset < output_size) {
        DWORD chunk = (DWORD)((output_size - offset) > 1048576
                                  ? 1048576
                                  : (output_size - offset));
        DWORD bytes_written = 0;
        if (!WriteFile(temp_file, output + offset, chunk, &bytes_written, NULL) ||
            bytes_written != chunk)
            goto cleanup;
        offset += bytes_written;
    }

    if (!FlushFileBuffers(temp_file))
        goto cleanup;
    if (!CloseHandle(temp_file)) {
        temp_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    temp_file = INVALID_HANDLE_VALUE;

    if (!MoveFileExA(temp_path, final_path, MOVEFILE_REPLACE_EXISTING))
        goto cleanup;

    temp_created = 0;
    result = 0;

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
    if (key_object != NULL) {
        SecureZeroMemory(key_object, object_length);
        free(key_object);
    }
    if (plaintext != NULL) {
        SecureZeroMemory(plaintext, plaintext_size != 0 ? plaintext_size : 1);
        free(plaintext);
    }
    if (output != NULL) {
        SecureZeroMemory(output, output_size);
        free(output);
    }
    free(final_path);
    free(temp_path);
    SecureZeroMemory(nonce, sizeof(nonce));
    return result;
}