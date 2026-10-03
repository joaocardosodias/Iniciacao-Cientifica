#include <windows.h>

int secure_erase(const char *path)
{
    HANDLE file;
    LARGE_INTEGER size;
    LARGE_INTEGER zero_position;
    BYTE zeros[65536] = {0};
    LONGLONG remaining;

    if (path == NULL) {
        return -1;
    }

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return -1;
    }

    if (!GetFileSizeEx(file, &size) || size.QuadPart < 0) {
        CloseHandle(file);
        return -1;
    }

    zero_position.QuadPart = 0;
    if (!SetFilePointerEx(file, zero_position, NULL, FILE_BEGIN)) {
        CloseHandle(file);
        return -1;
    }

    remaining = size.QuadPart;
    while (remaining > 0) {
        DWORD to_write = remaining > (LONGLONG)sizeof(zeros)
                            ? (DWORD)sizeof(zeros)
                            : (DWORD)remaining;
        DWORD written = 0;

        if (!WriteFile(file, zeros, to_write, &written, NULL) || written == 0) {
            CloseHandle(file);
            return -1;
        }
        remaining -= written;
    }

    if (!CloseHandle(file)) {
        return -1;
    }

    return DeleteFileA(path) ? 0 : -1;
}