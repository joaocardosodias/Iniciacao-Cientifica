#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * API:
 *
 * scan_storage() accepts a selection as a candidate name, a path relative to
 * HOME, a path beginning with "~/", or an absolute path. The explicit
 * allowed_dirs list contains candidate names only. A selection is scanned
 * only when it resolves to one of those authorized candidates.
 *
 * extensions contains suffixes including their leading dot (for example,
 * ".txt"). Matching is ASCII case-insensitive.
 *
 * On success, out receives dynamically allocated absolute file paths. The
 * caller must initialize out to {0} and release its contents with
 * scan_results_free(). On failure, scan_storage() releases any partial
 * results, leaves out empty, returns -1, and sets errno.
 *
 * The scanner never opens files; it enumerates metadata and does not modify,
 * copy, or transmit anything.
 */
typedef struct {
    char **paths;
    size_t count;
    size_t capacity;
} scan_results;

static const char *const storage_candidates[] = {
    "Documents",
    "Desktop",
    "Downloads",
    "Pictures",
    "Documentos",
    "Área de Trabalho",
    "Imagens",
    "Documentos_Teste"
};

static void scan_results_free(scan_results *results)
{
    size_t i;

    if (results == NULL)
        return;

    for (i = 0; i < results->count; ++i)
        free(results->paths[i]);

    free(results->paths);
    results->paths = NULL;
    results->count = 0;
    results->capacity = 0;
}

static int is_candidate_name(const char *name)
{
    size_t i;

    for (i = 0; i < sizeof(storage_candidates) / sizeof(storage_candidates[0]); ++i) {
        if (strcmp(name, storage_candidates[i]) == 0)
            return 1;
    }
    return 0;
}

static char *join_path(const char *left, const char *right)
{
    size_t left_len;
    size_t right_len;
    int add_slash;
    char *joined;

    if (left == NULL || right == NULL) {
        errno = EINVAL;
        return NULL;
    }

    left_len = strlen(left);
    right_len = strlen(right);
    add_slash = left_len == 0 || left[left_len - 1] != '/';

    if (left_len > SIZE_MAX - right_len - (size_t)add_slash - 1) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    joined = malloc(left_len + (size_t)add_slash + right_len + 1);
    if (joined == NULL)
        return NULL;

    memcpy(joined, left, left_len);
    if (add_slash)
        joined[left_len++] = '/';
    memcpy(joined + left_len, right, right_len);
    joined[left_len + right_len] = '\0';
    return joined;
}

static char *make_absolute_result_path(const char *root, const char *relative)
{
    size_t root_len;
    size_t relative_len;
    int add_slash;
    char *path;

    root_len = strlen(root);
    relative_len = strlen(relative);
    add_slash = root_len == 0 || root[root_len - 1] != '/';

    if (root_len > SIZE_MAX - relative_len - (size_t)add_slash - 1) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    path = malloc(root_len + (size_t)add_slash + relative_len + 1);
    if (path == NULL)
        return NULL;

    memcpy(path, root, root_len);
    if (add_slash)
        path[root_len++] = '/';
    memcpy(path + root_len, relative, relative_len);
    path[root_len + relative_len] = '\0';
    return path;
}

static int append_result(scan_results *results, char *path)
{
    char **new_paths;
    size_t new_capacity;

    if (results->count == results->capacity) {
        if (results->capacity == 0)
            new_capacity = 16;
        else {
            if (results->capacity > SIZE_MAX / 2 / sizeof(*results->paths)) {
                errno = ENOMEM;
                return -1;
            }
            new_capacity = results->capacity * 2;
        }

        if (new_capacity > SIZE_MAX / sizeof(*results->paths)) {
            errno = ENOMEM;
            return -1;
        }

        new_paths = realloc(results->paths, new_capacity * sizeof(*results->paths));
        if (new_paths == NULL)
            return -1;

        results->paths = new_paths;
        results->capacity = new_capacity;
    }

    results->paths[results->count++] = path;
    return 0;
}

static int extension_matches(const char *filename,
                             const char *const *extensions,
                             size_t extension_count)
{
    size_t filename_len = strlen(filename);
    size_t i;

    for (i = 0; i < extension_count; ++i) {
        size_t extension_len = strlen(extensions[i]);

        if (filename_len >= extension_len &&
            strcasecmp(filename + filename_len - extension_len, extensions[i]) == 0)
            return 1;
    }
    return 0;
}

static int make_relative_path(const char *parent,
                              const char *entry,
                              char **result)
{
    size_t parent_len;
    size_t entry_len;
    size_t separator;
    char *path;

    parent_len = strlen(parent);
    entry_len = strlen(entry);
    separator = parent_len != 0;

    if (parent_len > SIZE_MAX - entry_len - separator - 1) {
        errno = ENAMETOOLONG;
        return -1;
    }

    path = malloc(parent_len + separator + entry_len + 1);
    if (path == NULL)
        return -1;

    if (parent_len != 0) {
        memcpy(path, parent, parent_len);
        path[parent_len] = '/';
    }
    memcpy(path + parent_len + separator, entry, entry_len);
    path[parent_len + separator + entry_len] = '\0';
    *result = path;
    return 0;
}

/*
 * Walks only directory descriptors opened relative to the authorized root.
 * O_NOFOLLOW and fstatat(..., AT_SYMLINK_NOFOLLOW) prevent traversal through
 * symbolic links. The supplied directory descriptor remains owned by caller.
 */
static int scan_directory_fd(int directory_fd,
                             const char *root_path,
                             const char *relative_directory,
                             const char *const *extensions,
                             size_t extension_count,
                             scan_results *results)
{
    int duplicate_fd;
    DIR *directory;
    struct dirent *entry;
    int saved_errno = 0;

    duplicate_fd = dup(directory_fd);
    if (duplicate_fd < 0)
        return -1;

    directory = fdopendir(duplicate_fd);
    if (directory == NULL) {
        saved_errno = errno;
        close(duplicate_fd);
        errno = saved_errno;
        return -1;
    }

    for (;;) {
        struct stat entry_stat;
        char *relative_path = NULL;

        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            if (errno != 0)
                saved_errno = errno;
            break;
        }

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        if (fstatat(dirfd(directory), entry->d_name, &entry_stat,
                    AT_SYMLINK_NOFOLLOW) < 0) {
            saved_errno = errno;
            break;
        }

        if (S_ISLNK(entry_stat.st_mode))
            continue;

        if (!S_ISDIR(entry_stat.st_mode) && !S_ISREG(entry_stat.st_mode))
            continue;

        if (make_relative_path(relative_directory, entry->d_name,
                               &relative_path) < 0) {
            saved_errno = errno;
            break;
        }

        if (S_ISDIR(entry_stat.st_mode)) {
            int child_fd;
            struct stat opened_stat;

            child_fd = openat(dirfd(directory), entry->d_name,
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child_fd < 0) {
                saved_errno = errno;
                free(relative_path);
                break;
            }

            if (fstat(child_fd, &opened_stat) < 0) {
                saved_errno = errno;
                close(child_fd);
                free(relative_path);
                break;
            }

            if (!S_ISDIR(opened_stat.st_mode) ||
                opened_stat.st_dev != entry_stat.st_dev ||
                opened_stat.st_ino != entry_stat.st_ino) {
                saved_errno = EAGAIN;
                close(child_fd);
                free(relative_path);
                break;
            }

            if (scan_directory_fd(child_fd, root_path, relative_path,
                                  extensions, extension_count, results) < 0) {
                saved_errno = errno;
                close(child_fd);
                free(relative_path);
                break;
            }

            if (close(child_fd) < 0) {
                saved_errno = errno;
                free(relative_path);
                break;
            }
        } else if (extension_matches(entry->d_name, extensions, extension_count)) {
            char *absolute_path = make_absolute_result_path(root_path, relative_path);

            if (absolute_path == NULL) {
                saved_errno = errno;
                free(relative_path);
                break;
            }

            if (append_result(results, absolute_path) < 0) {
                saved_errno = errno;
                free(absolute_path);
                free(relative_path);
                break;
            }
        }

        free(relative_path);
    }

    if (closedir(directory) < 0 && saved_errno == 0)
        saved_errno = errno;

    if (saved_errno != 0) {
        errno = saved_errno;
        return -1;
    }

    return 0;
}

static int validate_extensions(const char *const *extensions,
                               size_t extension_count)
{
    size_t i;

    if (extensions == NULL || extension_count == 0) {
        errno = EINVAL;
        return -1;
    }

    for (i = 0; i < extension_count; ++i) {
        const unsigned char *p;

        if (extensions[i] == NULL || extensions[i][0] != '.' ||
            extensions[i][1] == '\0') {
            errno = EINVAL;
            return -1;
        }

        for (p = (const unsigned char *)extensions[i]; *p != '\0'; ++p) {
            if (*p == '/' || *p == '\\') {
                errno = EINVAL;
                return -1;
            }
        }
    }

    return 0;
}

static int resolve_selection(const char *home,
                            const char *selection,
                            char **resolved_selection)
{
    char *input_path = NULL;
    char *canonical_path;

    if (selection == NULL || selection[0] == '\0') {
        errno = EINVAL;
        return -1;
    }

    if (selection[0] == '/') {
        input_path = strdup(selection);
    } else if (selection[0] == '~' && selection[1] == '/') {
        input_path = join_path(home, selection + 2);
    } else {
        input_path = join_path(home, selection);
    }

    if (input_path == NULL)
        return -1;

    canonical_path = realpath(input_path, NULL);
    {
        int saved_errno = errno;
        free(input_path);
        errno = saved_errno;
    }

    if (canonical_path == NULL)
        return -1;

    *resolved_selection = canonical_path;
    return 0;
}

/*
 * Scan an explicitly authorized test candidate.
 *
 * allowed_dirs entries must exactly match one of the documented candidate
 * names above; arbitrary directory paths are not accepted in this list.
 */
int scan_storage(const char *selection,
                 const char *const *allowed_dirs,
                 size_t allowed_dir_count,
                 const char *const *extensions,
                 size_t extension_count,
                 scan_results *out)
{
    const char *home_environment;
    char *home = NULL;
    char *selected_path = NULL;
    char *candidate_path = NULL;
    char *canonical_candidate = NULL;
    int root_fd = -1;
    struct stat candidate_stat;
    struct stat opened_stat;
    size_t i;
    int authorized = 0;
    int result = -1;
    int saved_errno = 0;

    if (out == NULL) {
        errno = EINVAL;
        return -1;
    }

    if (out->paths != NULL || out->count != 0 || out->capacity != 0) {
        errno = EINVAL;
        return -1;
    }

    if (selection == NULL || selection[0] == '\0' ||
        allowed_dirs == NULL || allowed_dir_count == 0) {
        errno = EINVAL;
        return -1;
    }

    if (validate_extensions(extensions, extension_count) < 0)
        return -1;

    for (i = 0; i < allowed_dir_count; ++i) {
        size_t j;

        if (allowed_dirs[i] == NULL || !is_candidate_name(allowed_dirs[i])) {
            errno = EINVAL;
            return -1;
        }

        for (j = 0; j < i; ++j) {
            if (strcmp(allowed_dirs[i], allowed_dirs[j]) == 0) {
                errno = EINVAL;
                return -1;
            }
        }
    }

    home_environment = getenv("HOME");
    if (home_environment == NULL || home_environment[0] == '\0') {
        errno = ENOENT;
        return -1;
    }

    home = realpath(home_environment, NULL);
    if (home == NULL)
        return -1;

    {
        struct stat home_stat;

        if (stat(home, &home_stat) < 0) {
            saved_errno = errno;
            goto cleanup;
        }
        if (!S_ISDIR(home_stat.st_mode)) {
            saved_errno = ENOTDIR;
            goto cleanup;
        }
    }

    if (resolve_selection(home, selection, &selected_path) < 0) {
        saved_errno = errno;
        goto cleanup;
    }

    for (i = 0; i < allowed_dir_count; ++i) {
        struct stat candidate_lstat;
        char *candidate = join_path(home, allowed_dirs[i]);
        char *candidate_real;

        if (candidate == NULL) {
            saved_errno = errno;
            goto cleanup;
        }

        if (lstat(candidate, &candidate_lstat) < 0) {
            int candidate_errno = errno;
            free(candidate);

            if (candidate_errno == ENOENT || candidate_errno == ENOTDIR)
                continue;

            saved_errno = candidate_errno;
            goto cleanup;
        }

        if (!S_ISDIR(candidate_lstat.st_mode)) {
            free(candidate);
            continue;
        }

        candidate_real = realpath(candidate, NULL);
        {
            int candidate_errno = errno;
            free(candidate);
            if (candidate_real == NULL) {
                saved_errno = candidate_errno;
                goto cleanup;
            }
        }

        if (strcmp(selected_path, candidate_real) == 0) {
            candidate_path = join_path(home, allowed_dirs[i]);
            if (candidate_path == NULL) {
                saved_errno = errno;
                free(candidate_real);
                goto cleanup;
            }

            canonical_candidate = candidate_real;
            authorized = 1;
            break;
        }

        free(candidate_real);
    }

    if (!authorized) {
        saved_errno = EACCES;
        goto cleanup;
    }

    if (lstat(candidate_path, &candidate_stat) < 0) {
        saved_errno = errno;
        goto cleanup;
    }

    if (!S_ISDIR(candidate_stat.st_mode)) {
        saved_errno = ENOTDIR;
        goto cleanup;
    }

    root_fd = open(candidate_path,
                   O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (root_fd < 0) {
        saved_errno = errno;
        goto cleanup;
    }

    if (fstat(root_fd, &opened_stat) < 0) {
        saved_errno = errno;
        goto cleanup;
    }

    if (!S_ISDIR(opened_stat.st_mode) ||
        opened_stat.st_dev != candidate_stat.st_dev ||
        opened_stat.st_ino != candidate_stat.st_ino) {
        saved_errno = EAGAIN;
        goto cleanup;
    }

    if (scan_directory_fd(root_fd, canonical_candidate, "",
                          extensions, extension_count, out) < 0) {
        saved_errno = errno;
        goto cleanup;
    }

    result = 0;

cleanup:
    if (root_fd >= 0 && close(root_fd) < 0 && result == 0) {
        saved_errno = errno;
        result = -1;
    }

    free(home);
    free(selected_path);
    free(candidate_path);
    free(canonical_candidate);

    if (result < 0) {
        scan_results_free(out);
        errno = saved_errno != 0 ? saved_errno : EIO;
    }

    return result;
}

/* Test support. */
static int create_directory(const char *path)
{
    if (mkdir(path, 0700) == 0)
        return 0;
    return -1;
}

static int create_file(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC, 0600);

    if (fd < 0)
        return -1;
    return close(fd);
}

static int remove_tree_entry(const char *path,
                             const struct stat *status,
                             int type,
                             struct FTW *walk)
{
    (void)status;
    (void)type;
    (void)walk;
    return remove(path);
}

static int expect_scan_success(const char *selection,
                               const char *const *allowed,
                               size_t allowed_count,
                               const char *const *extensions,
                               size_t extension_count,
                               size_t expected_count)
{
    scan_results results = {0};
    int status = scan_storage(selection, allowed, allowed_count,
                              extensions, extension_count, &results);

    if (status != 0) {
        fprintf(stderr, "scan_storage(%s) failed: %s\n",
                selection, strerror(errno));
        scan_results_free(&results);
        return -1;
    }

    if (results.count != expected_count) {
        fprintf(stderr, "scan_storage(%s): expected %zu results, got %zu\n",
                selection, expected_count, results.count);
        scan_results_free(&results);
        return -1;
    }

    scan_results_free(&results);
    return 0;
}

static int run_scan_storage_tests(void)
{
    static const char *const candidate_extensions[] = { ".ok" };
    static const char *const text_extensions[] = { ".txt" };
    const char *old_home = getenv("HOME");
    char *saved_home = old_home != NULL ? strdup(old_home) : NULL;
    char template[] = "/tmp/scan-storage-test-XXXXXX";
    char *test_home = NULL;
    char *outside = NULL;
    char *path = NULL;
    char *nested = NULL;
    char *escape_link = NULL;
    char *file_link = NULL;
    scan_results results = {0};
    size_t i;
    int status = -1;

#define TEST_CHECK(condition, message) \
    do { \
        if (!(condition)) { \
            fprintf(stderr, "test failure: %s (errno=%d: %s)\n", \
                    message, errno, strerror(errno)); \
            goto cleanup; \
        } \
    } while (0)

    test_home = mkdtemp(template);
    TEST_CHECK(test_home != NULL, "mkdtemp");

    TEST_CHECK(setenv("HOME", test_home, 1) == 0, "set HOME");

    /* Resolve and scan every documented candidate relative to HOME. */
    for (i = 0; i < sizeof(storage_candidates) / sizeof(storage_candidates[0]); ++i) {
        const char *allowed[1] = { storage_candidates[i] };

        path = join_path(test_home, storage_candidates[i]);
        TEST_CHECK(path != NULL, "construct candidate path");
        TEST_CHECK(create_directory(path) == 0, "create candidate directory");

        nested = join_path(path, "candidate.ok");
        TEST_CHECK(nested != NULL, "construct candidate file path");
        TEST_CHECK(create_file(nested) == 0, "create candidate file");

        TEST_CHECK(expect_scan_success(storage_candidates[i], allowed, 1,
                                       candidate_extensions, 1, 1) == 0,
                   "resolve candidate name");

        free(path);
        path = NULL;
        free(nested);
        nested = NULL;
    }

    /* The explicit ~/Documentos_Teste spelling resolves to the authorized root. */
    {
        const char *allowed[] = { "Documentos_Teste" };

        TEST_CHECK(scan_storage("~/Documentos_Teste", allowed, 1,
                                candidate_extensions, 1, &results) == 0,
                   "resolve ~/Documentos_Teste");
        TEST_CHECK(results.count == 1, "Documentos_Teste result count");
        scan_results_free(&results);
    }

    /* Extension filtering is case-insensitive and recursive. */
    {
        const char *allowed[] = { "Documentos_Teste" };

        path = join_path(test_home, "Documentos_Teste");
        TEST_CHECK(path != NULL, "construct test directory");

        nested = join_path(path, "nested");
        TEST_CHECK(nested != NULL, "construct nested directory");
        TEST_CHECK(create_directory(nested) == 0, "create nested directory");

        free(path);
        path = NULL;

        path = join_path(nested, "inside.TXT");
        TEST_CHECK(path != NULL, "construct uppercase extension file");
        TEST_CHECK(create_file(path) == 0, "create uppercase extension file");
        free(path);
        path = NULL;

        path = join_path(nested, "ignored.bin");
        TEST_CHECK(path != NULL, "construct excluded file");
        TEST_CHECK(create_file(path) == 0, "create excluded file");
        free(path);
        path = NULL;

        TEST_CHECK(scan_storage("Documentos_Teste", allowed, 1,
                                text_extensions, 1, &results) == 0,
                   "scan extension-filter test");
        TEST_CHECK(results.count == 1, "extension filter and recursion");
        TEST_CHECK(strstr(results.paths[0], "inside.TXT") != NULL,
                   "case-insensitive extension match");
        scan_results_free(&results);
    }

    /* A candidate name omitted from the explicit allowlist is rejected. */
    {
        const char *allowed[] = { "Documentos_Teste" };

        errno = 0;
        TEST_CHECK(scan_storage("Documents", allowed, 1,
                                candidate_extensions, 1, &results) < 0,
                   "reject unauthorized candidate");
        TEST_CHECK(errno == EACCES, "unauthorized candidate errno");
        TEST_CHECK(results.paths == NULL && results.count == 0,
                   "no results after authorization failure");
    }

    /* Paths escaping HOME, or resolving outside the authorized candidate, fail. */
    {
        const char *allowed[] = { "Documentos_Teste" };

        errno = 0;
        TEST_CHECK(scan_storage("../outside", allowed, 1,
                                candidate_extensions, 1, &results) < 0,
                   "reject parent-directory escape");
        TEST_CHECK(results.paths == NULL && results.count == 0,
                   "no results after path escape");

        errno = 0;
        TEST_CHECK(scan_storage(test_home, allowed, 1,
                                candidate_extensions, 1, &results) < 0,
                   "reject HOME as selection");
    }

    /* Links to outside directories and files are never returned or traversed. */
    {
        const char *allowed[] = { "Documentos_Teste" };

        outside = join_path(test_home, "outside");
        TEST_CHECK(outside != NULL, "construct outside directory");
        TEST_CHECK(create_directory(outside) == 0, "create outside directory");

        path = join_path(outside, "leaked.txt");
        TEST_CHECK(path != NULL, "construct outside file");
        TEST_CHECK(create_file(path) == 0, "create outside file");
        free(path);
        path = NULL;

        path = join_path(test_home, "Documentos_Teste");
        TEST_CHECK(path != NULL, "construct authorized root");

        escape_link = join_path(path, "linked-directory");
        TEST_CHECK(escape_link != NULL, "construct directory link path");
        TEST_CHECK(symlink(outside, escape_link) == 0, "create directory symlink");

        file_link = join_path(path, "linked-file.txt");
        TEST_CHECK(file_link != NULL, "construct file link path");
        TEST_CHECK(symlink("../outside/leaked.txt", file_link) == 0,
                   "create file symlink");

        TEST_CHECK(scan_storage("Documentos_Teste", allowed, 1,
                                text_extensions, 1, &results) == 0,
                   "scan with escaping symlinks");
        for (i = 0; i < results.count; ++i) {
            TEST_CHECK(strstr(results.paths[i], "leaked.txt") == NULL,
                       "do not return linked file");
            TEST_CHECK(strstr(results.paths[i], "linked-directory") == NULL,
                       "do not traverse linked directory");
        }
        scan_results_free(&results);
    }

    /* Missing HOME has a documented, deterministic failure. */
    {
        const char *allowed[] = { "Documentos_Teste" };

        TEST_CHECK(unsetenv("HOME") == 0, "unset HOME");
        errno = 0;
        TEST_CHECK(scan_storage("Documentos_Teste", allowed, 1,
                                candidate_extensions, 1, &results) < 0,
                   "reject missing HOME");
        TEST_CHECK(errno == ENOENT, "missing HOME errno");
    }

    status = 0;

cleanup:
    scan_results_free(&results);
    free(path);
    free(nested);
    free(escape_link);
    free(file_link);
    free(outside);

    if (saved_home != NULL) {
        if (setenv("HOME", saved_home, 1) != 0)
            status = -1;
    } else {
        if (unsetenv("HOME") != 0)
            status = -1;
    }
    free(saved_home);

    if (test_home != NULL &&
        nftw(test_home, remove_tree_entry, 32, FTW_DEPTH | FTW_PHYS) < 0)
        status = -1;

#undef TEST_CHECK
    return status;
}

int main(void)
{
    if (run_scan_storage_tests() != 0)
        return EXIT_FAILURE;

    puts("scan_storage tests passed");
    return EXIT_SUCCESS;
}