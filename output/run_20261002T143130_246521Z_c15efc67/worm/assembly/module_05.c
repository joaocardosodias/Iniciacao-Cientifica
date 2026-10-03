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
    HANDLE output_file = INVALID_HANDLE_VALUE;
    BCRYPT_ALG_HANDLE algorithm = NULL;
    BCRYPT_KEY_HANDLE crypto_key = NULL;
    PUCHAR key_object = NULL;
    unsigned char *input_buffer = NULL;
    unsigned char *output_buffer = NULL;
    char *final_path = NULL;
    char *temporary_path = NULL;
    unsigned char nonce[12];
    unsigned char tag[16];
    BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO auth_info;
    LARGE_INTEGER file_size;
    ULONG key_object_size = 0;
    ULONG result_size = 0;
    ULONG ciphertext_size = 0;
    size_t input_size = 0;
    size_t final_path_size = 0;
    size_t temporary_path_size = 0;
    size_t offset = 0;
    size_t suffix_size;
    DWORD bytes_transferred;
    int result = -1;

    if (path == NULL || key == NULL || key_len != 32)
        goto cleanup;

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

    input_buffer = (unsigned char *)malloc(input_size == 0 ? 1 : input_size);
    if (input_buffer == NULL)
        goto cleanup;

    while (offset < input_size) {
        DWORD chunk = (DWORD)(input_size - offset);
        if (!ReadFile(input_file, input_buffer + offset, chunk,
                      &bytes_transferred, NULL) || bytes_transferred == 0)
            goto cleanup;
        offset += bytes_transferred;
    }

    if (!CloseHandle(input_file)) {
        input_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    input_file = INVALID_HANDLE_VALUE;

    if (!BCRYPT_SUCCESS(BCryptOpenAlgorithmProvider(&algorithm,
                                                     BCRYPT_AES_ALGORITHM,
                                                     NULL, 0)))
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptSetProperty(algorithm, BCRYPT_CHAINING_MODE,
                                          (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
                                          sizeof(BCRYPT_CHAIN_MODE_GCM), 0)))
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                                          (PUCHAR)&key_object_size,
                                          sizeof(key_object_size),
                                          &result_size, 0)) ||
        key_object_size == 0)
        goto cleanup;

    key_object = (PUCHAR)malloc(key_object_size);
    if (key_object == NULL)
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptGenerateSymmetricKey(algorithm, &crypto_key,
                                                    key_object,
                                                    key_object_size,
                                                    (PUCHAR)key,
                                                    (ULONG)key_len, 0)))
        goto cleanup;

    if (!BCRYPT_SUCCESS(BCryptGenRandom(NULL, nonce, sizeof(nonce),
                                        BCRYPT_USE_SYSTEM_PREFERRED_RNG)))
        goto cleanup;

    output_buffer = (unsigned char *)malloc(input_size + 29);
    if (output_buffer == NULL)
        goto cleanup;

    BCRYPT_INIT_AUTH_MODE_INFO(auth_info);
    auth_info.pbNonce = nonce;
    auth_info.cbNonce = sizeof(nonce);
    auth_info.pbTag = tag;
    auth_info.cbTag = sizeof(tag);

    if (!BCRYPT_SUCCESS(BCryptEncrypt(crypto_key, input_buffer,
                                      (ULONG)input_size, &auth_info,
                                      NULL, 0, output_buffer + 13,
                                      (ULONG)input_size, &ciphertext_size, 0)) ||
        ciphertext_size != (ULONG)input_size)
        goto cleanup;

    output_buffer[0] = (unsigned char)ENCRYPTED_FORMAT_VERSION;
    memcpy(output_buffer + 1, nonce, sizeof(nonce));
    memcpy(output_buffer + 13 + input_size, tag, sizeof(tag));

    if (!BCRYPT_SUCCESS(BCryptDestroyKey(crypto_key)))
        goto cleanup;
    crypto_key = NULL;

    if (!BCRYPT_SUCCESS(BCryptCloseAlgorithmProvider(algorithm, 0)))
        goto cleanup;
    algorithm = NULL;

    suffix_size = strlen(ENCRYPTED_SUFFIX);
    if (strlen(path) > SIZE_MAX - suffix_size - 1)
        goto cleanup;
    final_path_size = strlen(path) + suffix_size + 1;
    final_path = (char *)malloc(final_path_size);
    if (final_path == NULL)
        goto cleanup;

    memcpy(final_path, path, final_path_size - suffix_size - 1);
    memcpy(final_path + final_path_size - suffix_size - 1,
           ENCRYPTED_SUFFIX, suffix_size + 1);

    if (final_path_size > SIZE_MAX - 4)
        goto cleanup;
    temporary_path_size = final_path_size + 4;
    temporary_path = (char *)malloc(temporary_path_size);
    if (temporary_path == NULL)
        goto cleanup;

    memcpy(temporary_path, final_path, final_path_size - 1);
    memcpy(temporary_path + final_path_size - 1, ".tmp", 5);

    output_file = CreateFileA(temporary_path, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (output_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    offset = 0;
    while (offset < input_size + 29) {
        DWORD chunk = (DWORD)((input_size + 29 - offset) > MAXDWORD
                                  ? MAXDWORD
                                  : (input_size + 29 - offset));
        if (!WriteFile(output_file, output_buffer + offset, chunk,
                       &bytes_transferred, NULL) || bytes_transferred == 0)
            goto cleanup;
        offset += bytes_transferred;
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
    if (crypto_key != NULL)
        BCryptDestroyKey(crypto_key);
    if (algorithm != NULL)
        BCryptCloseAlgorithmProvider(algorithm, 0);
    if (result != 0 && temporary_path != NULL)
        DeleteFileA(temporary_path);
    free(key_object);
    free(input_buffer);
    free(output_buffer);
    free(final_path);
    free(temporary_path);
    return result;
}