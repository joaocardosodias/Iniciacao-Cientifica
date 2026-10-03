#include <windows.h>
#include <bcrypt.h>
#include <stddef.h>

int random_bytes(unsigned char *out, size_t len)
{
    size_t remaining = len;
    size_t max_chunk = (size_t)(ULONG)~(ULONG)0;

    if (len != 0 && out == NULL)
        return -1;

    while (remaining != 0) {
        ULONG chunk = (ULONG)(remaining > max_chunk ? max_chunk : remaining);
        NTSTATUS status = BCryptGenRandom(
            NULL,
            out,
            chunk,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        if (!BCRYPT_SUCCESS(status))
            return -1;

        out += chunk;
        remaining -= chunk;
    }

    return 0;
}