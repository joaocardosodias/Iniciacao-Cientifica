#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

static int storage_name_is_supported(const char *name)
{
    static const char *const names[] = {
        "Documents",
        "Desktop",
        "Downloads",
        "Pictures",
        "Documentos",
        "Área de Trabalho",
        "Imagens",
        "Documentos_Teste"
    };
    size_t i;

    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        if (strcmp(name, names[i]) == 0)
            return 1;
    }
    return 0;
}

static int validate_storage_tree(int dirfd, unsigned int depth)
{
    DIR *dir;
    struct dirent *entry;
    int scanfd;

    if (depth > 256) {
        errno = ELOOP;
        return -1;
    }

    scanfd = dup(dirfd);
    if (scanfd < 0)
        return -1;

    dir = fdopendir(scanfd);
    if (dir == NULL) {
        int saved_errno = errno;
        close(scanfd);
        errno = saved_errno;
        return -1;
    }

    for (;;) {
        struct stat st;

        errno = 0;
        entry = readdir(dir);
        if (entry == NULL) {
            if (errno != 0) {
                int saved_errno = errno;
                closedir(dir);
                errno = saved_errno;
                return -1;
            }
            break;
        }

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        if (fstatat(dirfd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0) {
            int saved_errno = errno;
            closedir(dir);
            errno = saved_errno;
            return -1;
        }

        if (S_ISLNK(st.st_mode))
            continue;

        if (S_ISDIR(st.st_mode)) {
            int childfd = openat(dirfd, entry->d_name,
                                 O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
            int result;
            int saved_errno;

            if (childfd < 0) {
                saved_errno = errno;
                closedir(dir);
                errno = saved_errno;
                return -1;
            }

            result = validate_storage_tree(childfd, depth + 1);
            saved_errno = errno;
            close(childfd);
            if (result < 0) {
                closedir(dir);
                errno = saved_errno;
                return -1;
            }
            continue;
        }

        if (S_ISREG(st.st_mode)) {
            char buffer[16384];
            ssize_t n;
            int filefd = openat(dirfd, entry->d_name,
                                O_RDONLY | O_NOFOLLOW | O_CLOEXEC);

            if (filefd < 0) {
                int saved_errno = errno;
                closedir(dir);
                errno = saved_errno;
                return -1;
            }

            for (;;) {
                n = read(filefd, buffer, sizeof(buffer));
                if (n > 0)
                    continue;
                if (n == 0)
                    break;
                if (errno == EINTR)
                    continue;

                {
                    int saved_errno = errno;
                    close(filefd);
                    closedir(dir);
                    errno = saved_errno;
                    return -1;
                }
            }

            if (close(filefd) < 0) {
                int saved_errno = errno;
                closedir(dir);
                errno = saved_errno;
                return -1;
            }
        }
    }

    if (closedir(dir) < 0)
        return -1;
    return 0;
}

int scan_storage(const char *configured_test_dir)
{
    const char *home;
    char *resolved_home = NULL;
    char *resolved_dir = NULL;
    char *parent;
    char *base;
    int rootfd = -1;
    struct stat st;
    int result = -1;
    int saved_errno;

    if (configured_test_dir == NULL || configured_test_dir[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    home = getenv("HOME");
    if (home == NULL || home[0] == '\0') {
        errno = ENOENT;
        return -1;
    }

    resolved_home = realpath(home, NULL);
    if (resolved_home == NULL)
        return -1;

    resolved_dir = realpath(configured_test_dir, NULL);
    if (resolved_dir == NULL) {
        saved_errno = errno;
        free(resolved_home);
        errno = saved_errno;
        return -1;
    }

    parent = strrchr(resolved_dir, '/');
    if (parent == NULL || parent == resolved_dir) {
        errno = EINVAL;
        goto cleanup;
    }

    base = parent + 1;
    *parent = '\0';

    if (strcmp(resolved_dir, resolved_home) != 0 ||
        !storage_name_is_supported(base)) {
        errno = EINVAL;
        goto cleanup;
    }

    rootfd = open(configured_test_dir,
                  O_RDONLY | O_DIRECTORY | O_NOFOLLOW | O_CLOEXEC);
    if (rootfd < 0)
        goto cleanup;

    if (fstat(rootfd, &st) < 0)
        goto cleanup;
    if (!S_ISDIR(st.st_mode)) {
        errno = ENOTDIR;
        goto cleanup;
    }

    result = validate_storage_tree(rootfd, 0);

cleanup:
    saved_errno = errno;
    if (rootfd >= 0)
        close(rootfd);
    free(resolved_dir);
    free(resolved_home);
    errno = saved_errno;
    return result;
}

#ifdef SCAN_STORAGE_TEST
#include <ftw.h>

static int remove_test_entry(const char *path, const struct stat *st,
                             int type, struct FTW *ftw)
{
    (void)st;
    (void)type;
    (void)ftw;
    return remove(path);
}

static int write_test_file(const char *path)
{
    FILE *file = fopen(path, "wb");

    if (file == NULL)
        return -1;
    if (fputs("validation test\n", file) == EOF) {
        int saved_errno = errno ? errno : EIO;
        fclose(file);
        errno = saved_errno;
        return -1;
    }
    if (fclose(file) != 0)
        return -1;
    return 0;
}

int main(void)
{
    static const char *const names[] = {
        "Documents",
        "Desktop",
        "Downloads",
        "Pictures",
        "Documentos",
        "Área de Trabalho",
        "Imagens",
        "Documentos_Teste"
    };
    char home_template[] = "/tmp/scan-storage-test-XXXXXX";
    char *home;
    char directory[PATH_MAX];
    char file[PATH_MAX];
    size_t i;
    int failed = 0;

    home = mkdtemp(home_template);
    if (home == NULL)
        return 1;

    if (setenv("HOME", home, 1) < 0) {
        nftw(home, remove_test_entry, 16, FTW_DEPTH | FTW_PHYS);
        return 1;
    }

    for (i = 0; i < sizeof(names) / sizeof(names[0]); ++i) {
        int n = snprintf(directory, sizeof(directory), "%s/%s", home, names[i]);
        if (n < 0 || (size_t)n >= sizeof(directory) ||
            mkdir(directory, 0700) < 0) {
            failed = 1;
            break;
        }

        n = snprintf(file, sizeof(file), "%s/test file.txt", directory);
        if (n < 0 || (size_t)n >= sizeof(file) || write_test_file(file) < 0 ||
            scan_storage(directory) != 0) {
            failed = 1;
            break;
        }
    }

    if (!failed) {
        int n = snprintf(directory, sizeof(directory), "%s/%s",
                         home, "Documentos_Teste");
        if (n < 0 || (size_t)n >= sizeof(directory)) {
            failed = 1;
        } else {
            char missing[PATH_MAX];
            n = snprintf(missing, sizeof(missing), "%s/%s",
                         home, "Documentos_Teste_inexistente");
            if (n < 0 || (size_t)n >= sizeof(missing) ||
                scan_storage(missing) == 0) {
                failed = 1;
            }
        }
    }

    if (nftw(home, remove_test_entry, 16, FTW_DEPTH | FTW_PHYS) < 0)
        failed = 1;

    return failed ? 1 : 0;
}
#endif