#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <dirent.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <errno.h>

/*
 * implementation_language_and_local_execution
 *
 * Purpose:
 *   Verify that this translation unit is compiled as a C program (not C++) and
 *   that, at runtime, no network sockets are open for the current process.
 *
 * Constraints:
 *   - Uses only the C standard library and POSIX headers.
 *   - No networking headers or functions are included or called.
 *   - Portable C99 (or later) code, clean compilation with -Wall -Wextra -pedantic.
 *
 * Compile‑time check:
 *   The macro __cplusplus is defined by C++ compilers.  If it is present,
 *   compilation aborts with an error.
 *
 * Runtime check (Linux):
 *   Scans /proc/self/fd and uses fstat() to examine each file descriptor.
 *   If any descriptor is of type S_IFSOCK, a socket is open and the function
 *   returns a non‑zero error code.
 *
 * Return values:
 *   0  – No sockets are open; the utility is confirmed to be C‑only and local.
 *   1  – At least one open socket was detected.
 *   2  – Runtime check could not be performed (e.g., not a Linux system).
 *
 * Platform notes:
 *   On non‑Linux systems the /proc filesystem may be unavailable; in that
 *   case the function returns 2 to indicate the inability to verify socket
 *   state.
 */

#ifndef __cplusplus
/* Compile‑time assertion that we are compiling as C (not C++) */
_Static_assert(1, "Compiled as C++ – this utility requires C compilation");
#else
#error "This source must be compiled as C, not C++"
#endif

static int is_socket_fd(int fd)
{
    struct stat st;
    if (fstat(fd, &st) == -1) {
        /* If fstat fails, assume not a socket; ignore the error */
        return 0;
    }
    return S_ISSOCK(st.st_mode);
}

/*
 * int implementation_language_and_local_execution(void);
 *
 * Checks for open network sockets in the current process. Returns 0 if none
 * are found, 1 if a socket is open, and 2 if the check cannot be performed.
 */
int implementation_language_and_local_execution(void)
{
#ifdef __linux__
    DIR *dir;
    struct dirent *entry;

    dir = opendir("/proc/self/fd");
    if (!dir) {
        /* Cannot open /proc/self/fd; treat as inability to verify */
        return 2;
    }

    while ((entry = readdir(dir)) != NULL) {
        /* Skip . and .. entries */
        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        /* Convert directory entry name to an integer file descriptor */
        char *endptr;
        long fd_long = strtol(entry->d_name, &endptr, 10);
        if (*endptr != '\0' || fd_long < 0)
            continue; /* Not a valid numeric FD */

        int fd = (int)fd_long;
        if (is_socket_fd(fd)) {
            closedir(dir);
            return 1; /* Socket found */
        }
    }

    closedir(dir);
    return 0; /* No sockets detected */
#else
    /* Non‑Linux platforms: cannot perform the check */
    return 2;
#endif
}