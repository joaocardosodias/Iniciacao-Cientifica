#define _GNU_SOURCE
#include <errno.h>
#include <limits.h>
#include <stdio.h>

int build_project(const char *project_dir)
{
    static const char makefile_contents[] =
        ".PHONY: all clean\n"
        "\n"
        "all: ferramenta\n"
        "\n"
        "ferramenta: main.c\n"
        "\tgcc -O2 -std=c11 -o ferramenta main.c -lssl -lcrypto -lcurl\n"
        "\n"
        "clean:\n"
        "\trm -f ferramenta *.o\n";
    char makefile_path[PATH_MAX];
    int path_length;
    FILE *file;

    if (project_dir == NULL || project_dir[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    path_length = snprintf(makefile_path, sizeof(makefile_path), "%s/Makefile",
                           project_dir);
    if (path_length < 0 || (size_t)path_length >= sizeof(makefile_path)) {
        errno = ENAMETOOLONG;
        return -1;
    }

    file = fopen(makefile_path, "w");
    if (file == NULL) {
        return -1;
    }

    errno = 0;
    if (fwrite(makefile_contents, 1, sizeof(makefile_contents) - 1, file) !=
        sizeof(makefile_contents) - 1) {
        int saved_errno = errno != 0 ? errno : EIO;
        (void)fclose(file);
        errno = saved_errno;
        return -1;
    }

    errno = 0;
    if (fclose(file) == EOF) {
        if (errno == 0) {
            errno = EIO;
        }
        return -1;
    }

    return 0;
}

/* Verificação: make -C "$dir" all && test -x "$dir/ferramenta" &&
   make -C "$dir" clean && test ! -e "$dir/ferramenta". */