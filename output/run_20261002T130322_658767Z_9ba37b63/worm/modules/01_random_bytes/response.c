#include <windows.h>
#include <bcrypt.h>
#include <limits.h>
#include <stddef.h>

int random_bytes(unsigned char *out, size_t len)
{
    unsigned char *p = out;

    if (len != 0 && out == NULL)
        return -1;

    while (len != 0) {
        ULONG chunk = len > (size_t)ULONG_MAX ? ULONG_MAX : (ULONG)len;
        NTSTATUS status = BCryptGenRandom(NULL, p, chunk, BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        if (status < 0)
            return -1;

        p += chunk;
        len -= chunk;
    }

    return 0;
}