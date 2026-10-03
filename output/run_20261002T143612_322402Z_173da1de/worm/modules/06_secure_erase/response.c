#include <windows.h>

int secure_erase(const char *path)
{
    HANDLE file;
    LARGE_INTEGER file_size;
    unsigned char zeros[65536] = {0};
    ULONGLONG remaining;

    if (path == NULL) {
        return -1;
    }

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return -1;
    }

    if (!GetFileSizeEx(file, &file_size) || file_size.QuadPart < 0) {
        CloseHandle(file);
        return -1;
    }

    remaining = (ULONGLONG)file_size.QuadPart;
    while (remaining > 0) {
        DWORD bytes_to_write = remaining > (ULONGLONG)sizeof(zeros)
                                   ? (DWORD)sizeof(zeros)
                                   : (DWORD)remaining;
        DWORD bytes_written = 0;

        if (!WriteFile(file, zeros, bytes_to_write, &bytes_written, NULL) ||
            bytes_written == 0) {
            CloseHandle(file);
            return -1;
        }

        remaining -= bytes_written;
    }

    if (!FlushFileBuffers(file)) {
        CloseHandle(file);
        return -1;
    }

    if (!CloseHandle(file)) {
        return -1;
    }

    return DeleteFileA(path) ? 0 : -1;
}