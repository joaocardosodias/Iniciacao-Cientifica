#include <windows.h>

int secure_erase(const char *path)
{
    HANDLE file;
    LARGE_INTEGER file_size;
    LONGLONG remaining;
    static const BYTE zeroes[65536] = { 0 };
    int result = -1;

    if (path == NULL)
        return -1;

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE)
        return -1;

    if (GetFileSizeEx(file, &file_size) && file_size.QuadPart >= 0) {
        remaining = file_size.QuadPart;
        while (remaining > 0) {
            DWORD requested = remaining > (LONGLONG)sizeof(zeroes)
                                  ? (DWORD)sizeof(zeroes)
                                  : (DWORD)remaining;
            DWORD written = 0;

            if (!WriteFile(file, zeroes, requested, &written, NULL) ||
                written == 0)
                goto cleanup;

            remaining -= written;
        }

        if (!FlushFileBuffers(file))
            goto cleanup;

        if (!CloseHandle(file))
            return -1;

        return DeleteFileA(path) ? 0 : -1;
    }

cleanup:
    CloseHandle(file);
    return result;
}