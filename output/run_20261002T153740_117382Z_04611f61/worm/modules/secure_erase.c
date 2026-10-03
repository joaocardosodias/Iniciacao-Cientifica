#include <windows.h>

int secure_erase(const char *path)
{
    HANDLE file;
    LARGE_INTEGER file_size;
    unsigned char zero_buffer[65536] = {0};
    ULONGLONG remaining;
    int success = 1;

    if (path == NULL) {
        return -1;
    }

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return -1;
    }

    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart < 0) {
        success = 0;
    } else {
        remaining = (ULONGLONG)file_size.QuadPart;
        while (remaining > 0) {
            DWORD amount = remaining > sizeof(zero_buffer)
                               ? (DWORD)sizeof(zero_buffer)
                               : (DWORD)remaining;
            DWORD written = 0;

            if (!WriteFile(file, zero_buffer, amount, &written, NULL) ||
                written == 0) {
                success = 0;
                break;
            }
            remaining -= written;
        }
    }

    if (success && !FlushFileBuffers(file)) {
        success = 0;
    }
    if (!CloseHandle(file)) {
        success = 0;
    }
    if (!success) {
        return -1;
    }

    return DeleteFileA(path) ? 0 : -1;
}