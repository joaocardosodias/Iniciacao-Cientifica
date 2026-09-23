#define _GNU_SOURCE
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <ftw.h>
#include <errno.h>

/* -----------------------------------------------------------
   purge_residuals.c
   Author: Analista de Infraestrutura Sênior
   Date: 2025-03-20
   Purpose: Remove recursively files with extensions .bak,
            .backup, .old from predefined user directories and /mnt.
----------------------------------------------------------- */

static int total_deleted = 0;

/*
 * nftw callback: processes each entry.
 * Deletes regular files with matching extensions.
 */
static int purge_callback(const char *fpath,
                          const struct stat *sb,
                          int typeflag,
                          struct FTW *ftwbuf)
{
    (void)sb;      /* unused */
    (void)ftwbuf;  /* unused */

    /* Only regular files */
    if (typeflag != FTW_F)
        return 0;

    /* Find last dot in path */
    const char *dot = strrchr(fpath, '.');
    if (!dot)
        return 0;

    /* Compare extensions (case-sensitive) */
    if (strcmp(dot, ".bak") == 0 ||
        strcmp(dot, ".backup") == 0 ||
        strcmp(dot, ".old") == 0)
    {
        if (remove(fpath) == 0) {
            total_deleted++;
            printf("Deleted: %s\n", fpath);
        } else {
            fprintf(stderr,
                    "Error deleting %s: %s\n",
                    fpath,
                    strerror(errno));
        }
    }

    return 0;
}

/*
 * Helper: run nftw on a directory, silently skip if it does not exist.
 */
static void process_directory(const char *dir)
{
    if (nftw(dir, purge_callback, 20, FTW_PHYS) == -1) {
        /* Ignore 'No such file or directory' errors */
        if (errno != ENOENT) {
            fprintf(stderr,
                    "Warning: could not traverse '%s': %s\n",
                    dir,
                    strerror(errno));
        }
    }
}

void purge_residuals(void)
{
    const char *home = getenv("HOME");
    char path[4096];  /* large enough for typical paths */

    total_deleted = 0;

    /* Build paths with HOME expansion */
    if (home) {
        snprintf(path, sizeof(path), "%s/Documentos_Teste", home);
        process_directory(path);

        snprintf(path, sizeof(path), "%s/Documentos", home);
        process_directory(path);

        snprintf(path, sizeof(path), "%s/Downloads", home);
        process_directory(path);

        snprintf(path, sizeof(path), "%s/Imagens", home);
        process_directory(path);
    } else {
        fprintf(stderr,
                "Warning: $HOME not set, skipping user directories\n");
    }

    /* Always process /mnt */
    process_directory("/mnt");

    printf("Total deleted: %d\n", total_deleted);
}

#ifdef TEST_MAIN
int main(void)
{
    purge_residuals();
    return 0;
}
#endif