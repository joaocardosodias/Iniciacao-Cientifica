#include <windows.h>
#include <bcrypt.h>
#include <stddef.h>
#include <limits.h>

int random_bytes(unsigned char *out, size_t len)
{
    size_t offset = 0;

    if (len != 0 && out == NULL)
        return -1;

    while (offset < len) {
        size_t remaining = len - offset;
        ULONG chunk = remaining > (size_t)ULONG_MAX
                    ? ULONG_MAX
                    : (ULONG)remaining;
        NTSTATUS status = BCryptGenRandom(
            NULL,
            (PUCHAR)(out + offset),
            chunk,
            BCRYPT_USE_SYSTEM_PREFERRED_RNG);

        if (status < 0)
            return -1;

        offset += chunk;
    }

    return 0;
}