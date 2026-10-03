#include <windows.h>
#include <bcrypt.h>
#include <stddef.h>

int random_bytes(unsigned char *out, size_t len)
{
    size_t offset = 0;
    const size_t max_chunk = (size_t)(ULONG)-1;

    if (len != 0 && out == NULL)
        return -1;

    while (offset < len) {
        size_t remaining = len - offset;
        ULONG chunk = (ULONG)(remaining > max_chunk ? max_chunk : remaining);
        NTSTATUS status = BCryptGenRandom(
            NULL,
            out + offset,
            chunk,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG
        );

        if (status < 0)
            return -1;

        offset += chunk;
    }

    return 0;
}