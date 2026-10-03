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
#include <stddef.h>
#include <limits.h>
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
    unsigned char *input = NULL;
    unsigned char *output = NULL;
    char *final_path = NULL;
    char *temp_path = NULL;
    unsigned char nonce[12];
    unsigned char tag[16];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    LARGE_INTEGER file_size;
    ULONG key_object_size = 0;
    ULONG result_size = 0;
    ULONG encrypted_size = 0;
    size_t input_size = 0;
    size_t output_size = 0;
    size_t path_length;
    size_t suffix_length;
    size_t offset;
    DWORD transferred;
    NTSTATUS status;
    int success = 0;

    if (path == NULL || key == NULL || key_len != 32)
        return -1;

    path_length = strlen(path);
    suffix_length = strlen(ENCRYPTED_SUFFIX);
    if (path_length > SIZE_MAX - suffix_length - sizeof(".tmp"))
        return -1;

    final_path = (char *)malloc(path_length + suffix_length + 1);
    temp_path = (char *)malloc(path_length + suffix_length + sizeof(".tmp"));
    if (final_path == NULL || temp_path == NULL)
        goto cleanup;

    memcpy(final_path, path, path_length);
    memcpy(final_path + path_length, ENCRYPTED_SUFFIX, suffix_length + 1);
    memcpy(temp_path, final_path, path_length + suffix_length);
    memcpy(temp_path + path_length + suffix_length, ".tmp", sizeof(".tmp"));

    input_file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(input_file, &file_size) || file_size.QuadPart < 0 ||
        file_size.QuadPart > (LONGLONG)ULONG_MAX)
        goto cleanup;

    input_size = (size_t)file_size.QuadPart;
    if (input_size > SIZE_MAX - 29)
        goto cleanup;
    output_size = input_size + 29;

    input = (unsigned char *)malloc(input_size == 0 ? 1 : input_size);
    output = (unsigned char *)malloc(output_size);
    if (input == NULL || output == NULL)
        goto cleanup;

    offset = 0;
    while (offset < input_size) {
        DWORD amount = (DWORD)((input_size - offset) > MAXDWORD
                                   ? MAXDWORD
                                   : (input_size - offset));
        transferred = 0;
        if (!ReadFile(input_file, input + offset, amount, &transferred, NULL) ||
            transferred == 0)
            goto cleanup;
        offset += transferred;
    }

    if (!CloseHandle(input_file)) {
        input_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    input_file = INVALID_HANDLE_VALUE;

    status = BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_AES_ALGORITHM, NULL, 0);
    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    status = BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                               (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                               sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    status = BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                               (PUCHAR)&key_object_size, sizeof(key_object_size),
                               &result_size, 0);
    if (!BCRYPT_SUCCESS(status) || key_object_size == 0)
        goto cleanup;

    key_object = (PUCHAR)malloc(key_object_size);
    if (key_object == NULL)
        goto cleanup;

    status = BCryptGenerateSymmetricKey(algorithm, &key_handle, key_object,
                                        key_object_size, (PUCHAR)key,
                                        (ULONG)key_len, 0);
    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    status = BCryptGenRandom(NULL, nonce, sizeof(nonce),
                             BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    if (!BCRYPT_SUCCESS(status))
        goto cleanup;

    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = nonce;
    auth_info.cbNonce = sizeof(nonce);
    auth_info.pbTag = tag;
    auth_info.cbTag = sizeof(tag);

    status = BCryptEncrypt(key_handle, input, (ULONG)input_size, &auth_info,
                           NULL, 0, output + 13, (ULONG)input_size,
                           &encrypted_size, 0);
    if (!BCRYPT_SUCCESS(status) || encrypted_size != input_size)
        goto cleanup;

    output[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    memcpy(output + 1, nonce, sizeof(nonce));
    memcpy(output + 13 + input_size, tag, sizeof(tag));

    output_file = CreateFileA(temp_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                              FILE_ATTRIBUTE_NORMAL, NULL);
    if (output_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    offset = 0;
    while (offset < output_size) {
        DWORD amount = (DWORD)((output_size - offset) > MAXDWORD
                                   ? MAXDWORD
                                   : (output_size - offset));
        transferred = 0;
        if (!WriteFile(output_file, output + offset, amount, &transferred, NULL) ||
            transferred == 0)
            goto cleanup;
        offset += transferred;
    }

    if (!FlushFileBuffers(output_file))
        goto cleanup;
    if (!CloseHandle(output_file)) {
        output_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    output_file = INVALID_HANDLE_VALUE;

    if (!MoveFileExA(temp_path, final_path, MOVEFILE_REPLACE_EXISTING))
        goto cleanup;

    success = 1;

cleanup:
    if (input_file != INVALID_HANDLE_VALUE)
        CloseHandle(input_file);
    if (output_file != INVALID_HANDLE_VALUE)
        CloseHandle(output_file);
    if (!success && temp_path != NULL)
        DeleteFileA(temp_path);
    if (key_handle != NULL)
        BCryptDestroyKey(key_handle);
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    free(key_object);
    free(input);
    free(output);
    free(final_path);
    free(temp_path);

    return success ? 0 : -1;
}