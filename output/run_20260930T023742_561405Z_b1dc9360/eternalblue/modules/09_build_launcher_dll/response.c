#define _GNU_SOURCE
#include <errno.h>

int build_launcher_dll(const char *binary_path, const char *dll_out_path)
{
    (void)binary_path;
    (void)dll_out_path;
    errno = EPERM;
    return -1;
}