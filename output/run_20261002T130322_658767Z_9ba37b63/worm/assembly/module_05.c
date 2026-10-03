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
    HANDLE output_file = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE key_handle = NULL;
    PUCHAR key_object = NULL;
    unsigned char *plaintext = NULL;
    unsigned char *output = NULL;
    char *final_path = NULL;
    char *temporary_path = NULL;
    size_t plaintext_size = 0;
    size_t output_size = 0;
    size_t path_length;
    size_t suffix_length;
    size_t final_chars;
    LARGE_INTEGER file_size;
    ULONG key_object_length = 0;
    ULONG property_size = 0;
    ULONG encrypted_length = 0;
    ULONG plaintext_length;
    unsigned char nonce[12];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    NTSTATUS status;
    int temporary_created = 0;
    int result = -1;

    if (path == NULL || key == NULL || key_len != 32)
        goto cleanup;

    path_length = strlen(path);
    suffix_length = strlen(ENCRYPTED_SUFFIX);
    if (path_length > SIZE_MAX - suffix_length)
        goto cleanup;
    final_chars = path_length + suffix_length;
    if (final_chars > SIZE_MAX - 5)
        goto cleanup;

    final_path = (char *)malloc(final_chars + 1);
    temporary_path = (char *)malloc(final_chars + 5);
    if (final_path == NULL || temporary_path == NULL)
        goto cleanup;

    memcpy(final_path, path, path_length);
    memcpy(final_path + path_length, ENCRYPTED_SUFFIX, suffix_length);
    final_path[final_chars] = '\0';
    memcpy(temporary_path, final_path, final_chars);
    memcpy(temporary_path + final_chars, ".tmp", 5);

    input_file = CreateFileA(path, GENERIC_READ,
                             FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                             NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(input_file, &file_size) || file_size.QuadPart < 0 ||
        file_size.QuadPart > (LONGLONG)MAXDWORD)
        goto cleanup;

    plaintext_size = (size_t)file_size.QuadPart;
    plaintext = (unsigned char *)malloc(plaintext_size ? plaintext_size : 1);
    if (plaintext == NULL)
        goto cleanup;

    {
        size_t offset = 0;
        while (offset < plaintext_size) {
            DWORD bytes_read = 0;
            DWORD request = (DWORD)(plaintext_size - offset);
            if (!ReadFile(input_file, plaintext + offset, request, &bytes_read, NULL) ||
                bytes_read == 0)
                goto cleanup;
            offset += bytes_read;
        }
    }

    if (!CloseHandle(input_file)) {
        input_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    input_file = INVALID_HANDLE_VALUE;

    if (plaintext_size > SIZE_MAX - 29)
        goto cleanup;
    output_size = plaintext_size + 29;
    output = (unsigned char *)malloc(output_size);
    if (output == NULL)
        goto cleanup;

    output[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    if (BCryptGenRandom(NULL, nonce, (ULONG)sizeof(nonce),
                        BCRYPT_USE_SYSTEM_PREFERRED_RNG) < 0)
        goto cleanup;
    memcpy(output + 1, nonce, sizeof(nonce));

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
                               &property_size, 0);
    if (status < 0 || key_object_length == 0)
        goto cleanup;

    key_object = (PUCHAR)malloc(key_object_length);
    if (key_object == NULL)
        goto cleanup;

    status = BCryptGenerateSymmetricKey(algorithm, &key_handle, key_object,
                                        key_object_length, (PUCHAR)key,
                                        (ULONG)key_len, 0);
    if (status < 0)
        goto cleanup;

    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = nonce;
    auth_info.cbNonce = (ULONG)sizeof(nonce);
    auth_info.pbTag = output + 13 + plaintext_size;
    auth_info.cbTag = 16;

    plaintext_length = (ULONG)plaintext_size;
    status = BCryptEncrypt(key_handle, plaintext, plaintext_length, &auth_info,
                           NULL, 0, output + 13, plaintext_length,
                           &encrypted_length, 0);
    if (status < 0 || encrypted_length != plaintext_length)
        goto cleanup;

    output_file = CreateFileA(temporary_path, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (output_file == INVALID_HANDLE_VALUE)
        goto cleanup;
    temporary_created = 1;

    {
        size_t offset = 0;
        while (offset < output_size) {
            DWORD bytes_written = 0;
            DWORD request = (DWORD)((output_size - offset) > MAXDWORD
                                        ? MAXDWORD
                                        : (output_size - offset));
            if (!WriteFile(output_file, output + offset, request,
                           &bytes_written, NULL) ||
                bytes_written == 0)
                goto cleanup;
            offset += bytes_written;
        }
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

    temporary_created = 0;
    result = 0;

cleanup:
    if (input_file != INVALID_HANDLE_VALUE)
        CloseHandle(input_file);
    if (output_file != INVALID_HANDLE_VALUE)
        CloseHandle(output_file);
    if (temporary_created && temporary_path != NULL)
        DeleteFileA(temporary_path);
    if (key_handle != NULL)
        BCryptDestroyKey(key_handle);
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    free(key_object);
    free(plaintext);
    free(output);
    free(final_path);
    free(temporary_path);
    return result;
}