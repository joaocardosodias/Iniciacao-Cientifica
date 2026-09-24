#define _GNU_SOURCE
#include <sys/types.h>
#include <sys/wait.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

/*
 * Build the project in project_dir by running its existing Makefile's "all"
 * target. If no Makefile exists, generate one from the caller-provided,
 * project-relative C source paths and executable name. The generated Makefile
 * provides "all" and "clean" targets and links only libssl, libcrypto, and
 * libcurl in addition to libc.
 *
 * Returns 0 on success, the make process's exit status on build failure, or
 * -1 on setup or process errors. Existing Makefiles are left unchanged.
 */
int build_project(const char *project_dir,
                  const char *executable,
                  const char *const *sources,
                  size_t source_count)
{
    const char *makefile_path = "Makefile";
    FILE *makefile;
    int makefile_exists;
    size_t i;
    pid_t child;
    int status;

    if (project_dir == NULL || project_dir[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    makefile_exists = access(project_dir, F_OK);
    if (makefile_exists != 0) {
        return -1;
    }

    {
        size_t length = strlen(project_dir);
        char *path = malloc(length + sizeof("/Makefile"));

        if (path == NULL) {
            return -1;
        }

        memcpy(path, project_dir, length);
        if (length > 0 && project_dir[length - 1] == '/') {
            memcpy(path + length, "Makefile", sizeof("Makefile"));
        } else {
            memcpy(path + length, "/Makefile", sizeof("/Makefile"));
        }

        makefile_exists = access(path, F_OK);
        free(path);
    }

    if (makefile_exists != 0 && errno != ENOENT) {
        return -1;
    }

    if (makefile_exists != 0) {
        size_t executable_length;

        if (executable == NULL || executable[0] == '\0' ||
            sources == NULL || source_count == 0) {
            errno = EINVAL;
            return -1;
        }

        executable_length = strlen(executable);
        for (i = 0; i < executable_length; ++i) {
            unsigned char c = (unsigned char)executable[i];
            if (!((c >= 'a' && c <= 'z') ||
                  (c >= 'A' && c <= 'Z') ||
                  (c >= '0' && c <= '9') ||
                  c == '_' || c == '-' || c == '.' || c == '/')) {
                errno = EINVAL;
                return -1;
            }
        }

        for (i = 0; i < source_count; ++i) {
            size_t j;
            size_t length;

            if (sources[i] == NULL || sources[i][0] == '\0') {
                errno = EINVAL;
                return -1;
            }

            length = strlen(sources[i]);
            if (length < 3 ||
                strcmp(sources[i] + length - 2, ".c") != 0) {
                errno = EINVAL;
                return -1;
            }

            for (j = 0; j < length; ++j) {
                unsigned char c = (unsigned char)sources[i][j];
                if (!((c >= 'a' && c <= 'z') ||
                      (c >= 'A' && c <= 'Z') ||
                      (c >= '0' && c <= '9') ||
                      c == '_' || c == '-' || c == '.' || c == '/')) {
                    errno = EINVAL;
                    return -1;
                }
            }
        }

        {
            size_t length = strlen(project_dir);
            char *path = malloc(length + sizeof("/Makefile"));

            if (path == NULL) {
                return -1;
            }

            memcpy(path, project_dir, length);
            if (length > 0 && project_dir[length - 1] == '/') {
                memcpy(path + length, "Makefile", sizeof("Makefile"));
            } else {
                memcpy(path + length, "/Makefile", sizeof("/Makefile"));
            }

            makefile = fopen(path, "w");
            free(path);
        }

        if (makefile == NULL) {
            return -1;
        }

        if (fprintf(makefile,
                    "CC ?= cc\n"
                    "CPPFLAGS ?=\n"
                    "CFLAGS ?= -std=c11 -O2 -Wall -Wextra\n"
                    "LDFLAGS ?=\n"
                    "LDLIBS ?= -lssl -lcrypto -lcurl\n"
                    "TARGET := %s\n"
                    "SOURCES := ",
                    executable) < 0) {
            fclose(makefile);
            return -1;
        }

        for (i = 0; i < source_count; ++i) {
            if (fprintf(makefile, "%s%s",
                         i == 0 ? "" : " ",
                         sources[i]) < 0) {
                fclose(makefile);
                return -1;
            }
        }

        if (fprintf(makefile, "\nOBJECTS := ") < 0) {
            fclose(makefile);
            return -1;
        }

        for (i = 0; i < source_count; ++i) {
            size_t length = strlen(sources[i]);

            if (fprintf(makefile, "%s%.*so",
                         i == 0 ? "" : " ",
                         (int)(length - 1), sources[i]) < 0) {
                fclose(makefile);
                return -1;
            }
        }

        if (fprintf(makefile,
                    "\n\n"
                    ".PHONY: all clean\n"
                    "all: $(TARGET)\n\n"
                    "$(TARGET): $(OBJECTS)\n"
                    "\t$(CC) $(CFLAGS) $(LDFLAGS) -o $@ $(OBJECTS) $(LDLIBS)\n\n"
                    "%%.o: %%.c\n"
                    "\t$(CC) $(CPPFLAGS) $(CFLAGS) -c -o $@ $<\n\n"
                    "clean:\n"
                    "\trm -f $(TARGET) $(OBJECTS)\n") < 0) {
            fclose(makefile);
            return -1;
        }

        if (fclose(makefile) != 0) {
            return -1;
        }
    }

    child = fork();
    if (child < 0) {
        return -1;
    }

    if (child == 0) {
        execlp("make", "make", "-C", project_dir, "all", (char *)NULL);
        _exit(127);
    }

    do {
        if (waitpid(child, &status, 0) >= 0) {
            break;
        }
    } while (errno == EINTR);

    if (errno != EINTR && status == 0) {
        return 0;
    }

    if (!WIFEXITED(status)) {
        return 1;
    }

    return WEXITSTATUS(status);
}