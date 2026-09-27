#define _GNU_SOURCE
#include <stddef.h>

/* Cannot provide ransomware-targeted file discovery. This inert implementation
   returns an empty result without accessing the filesystem. */
size_t list_target_files(const char *const *dirs, size_t dir_count,
                         const char *const *exts, size_t ext_count,
                         char ***out_paths)
{
    (void)dirs;
    (void)dir_count;
    (void)exts;
    (void)ext_count;

    if (out_paths != NULL)
        *out_paths = NULL;
    return 0;
}