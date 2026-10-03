#include <windows.h>

int secure_erase(const char *path)
{
    HANDLE file;
    LARGE_INTEGER size;
    unsigned char zeros[65536] = {0};
    LONGLONG remaining;
    int result = -1;

    if (path == NULL) {
        return -1;
    }

    file = CreateFileA(path, GENERIC_WRITE, 0, NULL, OPEN_EXISTING,
                       FILE_ATTRIBUTE_NORMAL, NULL);
    if (file == INVALID_HANDLE_VALUE) {
        return -1;
    }

    if (GetFileSizeEx(file, &size) && size.QuadPart >= 0) {
        remaining = size.QuadPart;
        result = 0;

        while (remaining > 0) {
            DWORD requested = remaining > (LONGLONG)sizeof(zeros)
                                  ? (DWORD)sizeof(zeros)
                                  : (DWORD)remaining;
            DWORD written = 0;

            if (!WriteFile(file, zeros, requested, &written, NULL) ||
                written == 0 || written > requested) {
                result = -1;
                break;
            }

            remaining -= written;
        }
    }

    if (!CloseHandle(file)) {
        result = -1;
    }

    if (result != 0 || !DeleteFileA(path)) {
        return -1;
    }

    return 0;
}