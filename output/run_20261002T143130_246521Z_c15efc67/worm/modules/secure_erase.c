#include <windows.h>

int secure_erase(const char *path)
{
    HANDLE file;
    LARGE_INTEGER file_size;
    LARGE_INTEGER zero_offset;
    unsigned char zero_buffer[65536] = {0};
    ULONGLONG remaining;
    BOOL operation_ok = TRUE;
    BOOL close_ok;

    if (path == NULL) {
        return -1;
    }

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return -1;
    }

    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart < 0) {
        operation_ok = FALSE;
    }

    zero_offset.QuadPart = 0;
    if (operation_ok && !SetFilePointerEx(file, zero_offset, NULL, FILE_BEGIN)) {
        operation_ok = FALSE;
    }

    remaining = operation_ok ? (ULONGLONG)file_size.QuadPart : 0;
    while (operation_ok && remaining != 0) {
        DWORD chunk = remaining > sizeof(zero_buffer)
                          ? (DWORD)sizeof(zero_buffer)
                          : (DWORD)remaining;
        DWORD written = 0;

        if (!WriteFile(file, zero_buffer, chunk, &written, NULL) || written == 0) {
            operation_ok = FALSE;
            break;
        }

        remaining -= written;
    }

    if (operation_ok && !FlushFileBuffers(file)) {
        operation_ok = FALSE;
    }

    close_ok = CloseHandle(file);
    if (!operation_ok || !close_ok) {
        return -1;
    }

    return DeleteFileA(path) ? 0 : -1;
}