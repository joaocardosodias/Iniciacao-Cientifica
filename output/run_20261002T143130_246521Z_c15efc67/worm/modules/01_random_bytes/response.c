#include <windows.h>
#include <bcrypt.h>
#include <limits.h>
#include <stddef.h>

int random_bytes(unsigned char *out, size_t len)
{
    NTSTATUS status;

    if (len == 0)
        return 0;
    if (out == NULL || len > (size_t)ULONG_MAX)
        return -1;

    status = BCryptGenRandom(NULL, out, (ULONG)len, BCRYPT_USE_SYSTEM_PREFERRED_RNG);
    return status >= 0 ? 0 : -1;
}