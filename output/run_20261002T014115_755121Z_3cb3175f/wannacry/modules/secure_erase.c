#include <windows.h>

int secure_erase(const char *path)
{
    HANDLE file;
    LARGE_INTEGER fileSize;
    ULONGLONG remaining;
    char zeros[4096] = { 0 };

    if (path == NULL)
        return -1;

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return -1;

    if (!GetFileSizeEx(file, &fileSize) || fileSize.QuadPart < 0) {
        CloseHandle(file);
        return -1;
    }

    remaining = (ULONGLONG)fileSize.QuadPart;
    while (remaining > 0) {
        DWORD chunk = remaining > sizeof(zeros)
                          ? (DWORD)sizeof(zeros)
                          : (DWORD)remaining;
        DWORD written = 0;

        if (!WriteFile(file, zeros, chunk, &written, NULL) || written == 0) {
            CloseHandle(file);
            return -1;
        }
        remaining -= written;
    }

    if (!CloseHandle(file))
        return -1;

    return DeleteFileA(path) ? 0 : -1;
}