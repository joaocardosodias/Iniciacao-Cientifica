#include <windows.h>
#include <bcrypt.h>
#include <limits.h>
#include <stddef.h>

int random_bytes(unsigned char *out, size_t len)
{
    if (len != 0 && out == NULL)
        return -1;

    while (len != 0) {
        ULONG chunk = len > ULONG_MAX ? ULONG_MAX : (ULONG)len;
        NTSTATUS status = BCryptGenRandom(
            NULL,
            out,
            chunk,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );

        if (status < 0)
            return -1;

        out += chunk;
        len -= chunk;
    }

    return 0;
}