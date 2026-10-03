#include <windows.h>

int secure_erase(const char *path)
{
    HANDLE file;
    LARGE_INTEGER size;
    LARGE_INTEGER zero_offset;
    unsigned char zero_buffer[65536] = {0};
    LONGLONG remaining;
    int success = 1;

    if (path == NULL) {
        return -1;
    }

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return -1;
    }

    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0) {
        success = 0;
    } else {
        zero_offset.QuadPart = 0;
        if (!SetFilePointerEx(file, zero_offset, NULL, FILE_BEGIN)) {
            success = 0;
        } else {
            remaining = size.QuadPart;
            while (success && remaining > 0) {
                DWORD request = remaining > (LONGLONG)sizeof(zero_buffer)
                                    ? (DWORD)sizeof(zero_buffer)
                                    : (DWORD)remaining;
                DWORD written = 0;

                if (!WriteFile(file, zero_buffer, request, &written, NULL) ||
                    written == 0) {
                    success = 0;
                    break;
                }
                remaining -= written;
            }
        }
    }

    if (success && !FlushFileBuffers(file)) {
        success = 0;
    }

    if (!CloseHandle(file)) {
        success = 0;
    }

    if (!success || !DeleteFileA(path)) {
        return -1;
    }

    return 0;
}