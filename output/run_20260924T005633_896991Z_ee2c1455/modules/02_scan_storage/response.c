#define _GNU_SOURCE
#include <ctype.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

/*
 * Each root in storage_config.roots is an explicitly configured path.
 * A root is scanned only when its authorized field is true. Relative paths
 * and ~/ paths are resolved against a validated absolute HOME; if HOME is
 * absent or invalid, those roots are skipped. No roots are inferred.
 *
 * The named candidates below are informational: they are accepted by the
 * same explicit-configuration and authorization rules as any other path.
 * Extensions are matched case-insensitively against the final suffix.
 * Traversal uses descriptor-relative operations and O_NOFOLLOW, so symbolic
 * links encountered beneath an authorized root are not followed.
 */

typedef struct {
    const char *path;
    bool authorized;
} storage_root;

typedef struct {
    const storage_root *roots;
    size_t root_count;
    const char *const *extensions;
    size_t extension_count;
} storage_config;

typedef struct {
    char **paths;
    size_t count;
    size_t capacity;
} storage_index;

static const char *const named_storage_candidates[] = {
    "~/Documents",
    "~/Desktop",
    "~/Downloads",
    "~/Pictures",
    "~/Documentos",
    "~/Área de Trabalho",
    "~/Imagens",
    "~/Documentos_Teste"
};

const char *const *scan_storage_named_candidates(size_t *count)
{
    if (count != NULL)
        *count = sizeof(named_storage_candidates) / sizeof(named_storage_candidates[0]);
    return named_storage_candidates;
}

static bool path_has_parent_component(const char *path)
{
    const char *p = path;

    if (path == NULL)
        return true;

    while (*p != '\0') {
        const char *start;
        size_t length;

        while (*p == '/')
            p++;
        if (*p == '\0')
            break;

        start = p;
        while (*p != '\0' && *p != '/')
            p++;
        length = (size_t)(p - start);

        if (length == 2 && start[0] == '.' && start[1] == '.')
            return true;
    }

    return false;
}

static char *normalize_absolute_path(const char *path)
{
    char *copy;
    char *saveptr = NULL;
    char *token;
    char *result;
    size_t result_length = 1;
    size_t component_count = 0;
    size_t capacity;

    if (path == NULL || path[0] != '/' || path_has_parent_component(path)) {
        errno = EINVAL;
        return NULL;
    }

    capacity = strlen(path) + 2;
    copy = strdup(path);
    result = malloc(capacity);
    if (copy == NULL || result == NULL) {
        free(copy);
        free(result);
        return NULL;
    }

    result[0] = '/';
    result[1] = '\0';

    for (token = strtok_r(copy, "/", &saveptr);
         token != NULL;
         token = strtok_r(NULL, "/", &saveptr)) {
        size_t token_length = strlen(token);
        size_t needed;

        if (strcmp(token, ".") == 0 || token_length == 0)
            continue;

        needed = result_length + (component_count == 0 ? 0 : 1) + token_length + 1;
        if (needed > capacity) {
            size_t new_capacity = capacity;
            char *new_result;

            while (new_capacity < needed) {
                if (new_capacity > SIZE_MAX / 2) {
                    free(copy);
                    free(result);
                    errno = ENOMEM;
                    return NULL;
                }
                new_capacity *= 2;
            }
            new_result = realloc(result, new_capacity);
            if (new_result == NULL) {
                free(copy);
                free(result);
                return NULL;
            }
            result = new_result;
            capacity = new_capacity;
        }

        if (component_count != 0)
            result[result_length++] = '/';
        memcpy(result + result_length, token, token_length);
        result_length += token_length;
        result[result_length] = '\0';
        component_count++;
    }

    free(copy);
    return result;
}

/*
 * Open an absolute directory without following any symbolic-link component.
 * The caller owns the returned descriptor. The input must already be
 * normalized and must not contain parent components.
 */
static int open_absolute_directory_nofollow(const char *path)
{
    int current_fd;
    char *copy;
    char *saveptr = NULL;
    char *token;

    if (path == NULL || path[0] != '/' || path_has_parent_component(path)) {
        errno = EINVAL;
        return -1;
    }

    current_fd = open("/", O_RDONLY | O_DIRECTORY | O_CLOEXEC);
    if (current_fd < 0)
        return -1;

    copy = strdup(path);
    if (copy == NULL) {
        close(current_fd);
        return -1;
    }

    for (token = strtok_r(copy, "/", &saveptr);
         token != NULL;
         token = strtok_r(NULL, "/", &saveptr)) {
        int next_fd;

        if (strcmp(token, ".") == 0 || token[0] == '\0')
            continue;

        next_fd = openat(current_fd, token,
                         O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next_fd < 0) {
            int saved_errno = errno;
            free(copy);
            close(current_fd);
            errno = saved_errno;
            return -1;
        }

        close(current_fd);
        current_fd = next_fd;
    }

    free(copy);
    return current_fd;
}

static bool valid_extension_entry(const char *extension)
{
    const unsigned char *p;
    const char *start;

    if (extension == NULL || extension[0] == '\0')
        return false;

    start = extension[0] == '.' ? extension + 1 : extension;
    if (*start == '\0')
        return false;

    for (p = (const unsigned char *)start; *p != '\0'; p++) {
        if (*p == '/' || *p == '\\' || *p == '.')
            return false;
    }

    return true;
}

static bool extension_is_allowed(const char *name,
                                 const storage_config *config)
{
    const char *dot;
    size_t i;

    dot = strrchr(name, '.');
    if (dot == NULL || dot == name || dot[1] == '\0')
        return false;

    for (i = 0; i < config->extension_count; i++) {
        const char *allowed = config->extensions[i];
        const char *suffix;

        if (!valid_extension_entry(allowed))
            continue;

        suffix = allowed[0] == '.' ? allowed + 1 : allowed;
        if (strcasecmp(dot + 1, suffix) == 0)
            return true;
    }

    return false;
}

static int index_add(storage_index *index, const char *path)
{
    size_t i;
    char *copy;

    for (i = 0; i < index->count; i++) {
        if (strcmp(index->paths[i], path) == 0)
            return 0;
    }

    if (index->count == index->capacity) {
        size_t new_capacity = index->capacity == 0 ? 16 : index->capacity * 2;
        char **new_paths;

        if (new_capacity < index->capacity ||
            new_capacity > SIZE_MAX / sizeof(*index->paths)) {
            errno = ENOMEM;
            return -1;
        }

        new_paths = realloc(index->paths, new_capacity * sizeof(*index->paths));
        if (new_paths == NULL)
            return -1;

        index->paths = new_paths;
        index->capacity = new_capacity;
    }

    copy = strdup(path);
    if (copy == NULL)
        return -1;

    index->paths[index->count++] = copy;
    return 0;
}

static char *join_index_path(const char *root, const char *relative)
{
    size_t root_length = strlen(root);
    size_t relative_length = strlen(relative);
    size_t separator = root_length == 1 && root[0] == '/' ? 0 : 1;
    size_t total;
    char *result;

    if (root_length > SIZE_MAX - relative_length - separator - 1) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    total = root_length + separator + relative_length + 1;
    result = malloc(total);
    if (result == NULL)
        return NULL;

    memcpy(result, root, root_length);
    if (separator != 0)
        result[root_length] = '/';
    memcpy(result + root_length + separator, relative, relative_length);
    result[total - 1] = '\0';
    return result;
}

static char *join_relative_path(const char *parent, const char *name)
{
    size_t parent_length = strlen(parent);
    size_t name_length = strlen(name);
    size_t separator = parent_length == 0 ? 0 : 1;
    size_t total;
    char *result;

    if (parent_length > SIZE_MAX - name_length - separator - 1) {
        errno = ENAMETOOLONG;
        return NULL;
    }

    total = parent_length + separator + name_length + 1;
    result = malloc(total);
    if (result == NULL)
        return NULL;

    if (parent_length != 0)
        memcpy(result, parent, parent_length);
    if (separator != 0)
        result[parent_length] = '/';
    memcpy(result + parent_length + separator, name, name_length);
    result[total - 1] = '\0';
    return result;
}

/*
 * Filesystem errors for individual entries are deliberately local: an
 * inaccessible or concurrently removed entry is skipped, while allocation
 * failures abort the scan. The supplied directory descriptor is not owned.
 */
static int scan_directory_fd(int directory_fd,
                             const char *root_path,
                             const char *relative_directory,
                             const storage_config *config,
                             storage_index *index)
{
    int duplicate_fd;
    DIR *directory;
    struct dirent *entry;
    int result = 0;

    duplicate_fd = dup(directory_fd);
    if (duplicate_fd < 0)
        return 0;

    directory = fdopendir(duplicate_fd);
    if (directory == NULL) {
        close(duplicate_fd);
        return 0;
    }

    errno = 0;
    while ((entry = readdir(directory)) != NULL) {
        struct stat st;
        char *relative_path = NULL;

        if (strcmp(entry->d_name, ".") == 0 ||
            strcmp(entry->d_name, "..") == 0)
            continue;

        if (fstatat(directory_fd, entry->d_name, &st, AT_SYMLINK_NOFOLLOW) < 0)
            continue;

        if (S_ISDIR(st.st_mode)) {
            int child_fd;

            child_fd = openat(directory_fd, entry->d_name,
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child_fd < 0)
                continue;

            relative_path = join_relative_path(relative_directory, entry->d_name);
            if (relative_path == NULL) {
                close(child_fd);
                result = -1;
                break;
            }

            if (scan_directory_fd(child_fd, root_path, relative_path,
                                  config, index) < 0)
                result = -1;

            free(relative_path);
            close(child_fd);
            if (result < 0)
                break;
        } else if (S_ISREG(st.st_mode) &&
                   extension_is_allowed(entry->d_name, config)) {
            char *file_relative;
            char *full_path;

            file_relative = join_relative_path(relative_directory, entry->d_name);
            if (file_relative == NULL) {
                result = -1;
                break;
            }

            full_path = join_index_path(root_path, file_relative);
            free(file_relative);
            if (full_path == NULL) {
                result = -1;
                break;
            }

            if (index_add(index, full_path) < 0)
                result = -1;

            free(full_path);
            if (result < 0)
                break;
        }

        errno = 0;
    }

    if (entry == NULL && errno != 0 && result == 0) {
        /* A readdir error is local to this directory; continue elsewhere. */
    }

    closedir(directory);
    return result;
}

/*
 * Resolve a configured root. The returned descriptor is open on success;
 * resolved_path is allocated and contains its normalized absolute path.
 * Relative roots and ~/ roots require a valid HOME.
 */
static int resolve_configured_root(const char *configured_path,
                                   const char *home,
                                   char **resolved_path)
{
    char *expanded = NULL;
    char *normalized = NULL;
    int fd = -1;
    size_t home_length;
    size_t path_length;
    bool needs_home;

    *resolved_path = NULL;

    if (configured_path == NULL || configured_path[0] == '\0' ||
        path_has_parent_component(configured_path)) {
        errno = EINVAL;
        return -1;
    }

    needs_home = configured_path[0] != '/';
    if (configured_path[0] == '~' &&
        (configured_path[1] == '/' || configured_path[1] == '\0'))
        needs_home = true;

    if (needs_home && (home == NULL || home[0] != '/')) {
        errno = ENOENT;
        return -1;
    }

    if (configured_path[0] == '/') {
        expanded = strdup(configured_path);
    } else if (configured_path[0] == '~' &&
               (configured_path[1] == '/' || configured_path[1] == '\0')) {
        const char *tail = configured_path[1] == '/' ? configured_path + 2 : "";

        home_length = strlen(home);
        path_length = strlen(tail);
        if (home_length > SIZE_MAX - path_length - 2) {
            errno = ENAMETOOLONG;
            return -1;
        }

        expanded = malloc(home_length + path_length + 2);
        if (expanded != NULL) {
            memcpy(expanded, home, home_length);
            if (path_length != 0) {
                expanded[home_length] = '/';
                memcpy(expanded + home_length + 1, tail, path_length);
                expanded[home_length + path_length + 1] = '\0';
            } else {
                expanded[home_length] = '\0';
            }
        }
    } else {
        home_length = strlen(home);
        path_length = strlen(configured_path);
        if (home_length > SIZE_MAX - path_length - 2) {
            errno = ENAMETOOLONG;
            return -1;
        }

        expanded = malloc(home_length + path_length + 2);
        if (expanded != NULL) {
            memcpy(expanded, home, home_length);
            expanded[home_length] = '/';
            memcpy(expanded + home_length + 1, configured_path, path_length);
            expanded[home_length + path_length + 1] = '\0';
        }
    }

    if (expanded == NULL)
        return -1;

    if (path_has_parent_component(expanded)) {
        free(expanded);
        errno = EINVAL;
        return -1;
    }

    normalized = normalize_absolute_path(expanded);
    free(expanded);
    if (normalized == NULL)
        return -1;

    fd = open_absolute_directory_nofollow(normalized);
    if (fd < 0) {
        free(normalized);
        return -1;
    }

    *resolved_path = normalized;
    return fd;
}

/*
 * Index regular files under explicitly configured, authorized roots.
 * Returns 0 when the scan completed (individual filesystem errors are
 * skipped), or -1 for invalid arguments or resource-allocation failures.
 * The caller owns the resulting paths and must call storage_index_free().
 */
int scan_storage(const storage_config *config, storage_index *index)
{
    const char *home_environment;
    char *home_normalized = NULL;
    int home_fd = -1;
    size_t i;
    int result = 0;

    if (config == NULL || index == NULL ||
        (config->root_count != 0 && config->roots == NULL) ||
        (config->extension_count != 0 && config->extensions == NULL)) {
        errno = EINVAL;
        return -1;
    }

    index->paths = NULL;
    index->count = 0;
    index->capacity = 0;

    home_environment = getenv("HOME");
    if (home_environment != NULL && home_environment[0] == '/') {
        home_normalized = normalize_absolute_path(home_environment);
        if (home_normalized != NULL) {
            home_fd = open_absolute_directory_nofollow(home_normalized);
            if (home_fd < 0) {
                free(home_normalized);
                home_normalized = NULL;
            }
        }
    }

    if (home_fd >= 0)
        close(home_fd);

    for (i = 0; i < config->root_count; i++) {
        char *root_path = NULL;
        int root_fd;

        if (!config->roots[i].authorized)
            continue;

        root_fd = resolve_configured_root(config->roots[i].path,
                                          home_normalized, &root_path);
        if (root_fd < 0)
            continue;

        if (scan_directory_fd(root_fd, root_path, "", config, index) < 0)
            result = -1;

        close(root_fd);
        free(root_path);

        if (result < 0)
            break;
    }

    free(home_normalized);

    if (result < 0)
        storage_index_free(index);

    return result;
}

void storage_index_free(storage_index *index)
{
    size_t i;

    if (index == NULL)
        return;

    for (i = 0; i < index->count; i++)
        free(index->paths[i]);

    free(index->paths);
    index->paths = NULL;
    index->count = 0;
    index->capacity = 0;
}

#ifdef SCAN_STORAGE_TEST

#include <assert.h>
#include <limits.h>
#include <sys/wait.h>

static void test_make_directory(const char *path)
{
    char *copy = strdup(path);
    char *p;

    assert(copy != NULL);
    for (p = copy + 1; *p != '\0'; p++) {
        if (*p == '/') {
            *p = '\0';
            if (mkdir(copy, 0700) < 0)
                assert(errno == EEXIST);
            *p = '/';
        }
    }
    if (mkdir(copy, 0700) < 0)
        assert(errno == EEXIST);
    free(copy);
}

static void test_write_file(const char *path)
{
    int fd = open(path, O_WRONLY | O_CREAT | O_TRUNC | O_CLOEXEC, 0600);
    assert(fd >= 0);
    assert(close(fd) == 0);
}

static bool index_contains(const storage_index *index, const char *path)
{
    size_t i;

    for (i = 0; i < index->count; i++) {
        if (strcmp(index->paths[i], path) == 0)
            return true;
    }
    return false;
}

static void test_join(char *output, size_t size,
                      const char *first, const char *second)
{
    int n = snprintf(output, size, "%s/%s", first, second);
    assert(n >= 0 && (size_t)n < size);
}

static void test_scan_storage(void)
{
    char temporary[] = "/tmp/scan-storage-test-XXXXXX";
    char *base = mkdtemp(temporary);
    char home[PATH_MAX];
    char authorized[PATH_MAX];
    char nested[PATH_MAX];
    char denied[PATH_MAX];
    char outside[PATH_MAX];
    char path[PATH_MAX];
    char link_path[PATH_MAX];
    char *candidate_dirs[8];
    const char *candidate_names[] = {
        "Documents", "Desktop", "Downloads", "Pictures",
        "Documentos", "Área de Trabalho", "Imagens", "Documentos_Teste"
    };
    const char *extensions[] = { ".txt", "pdf" };
    storage_index index = {0};
    storage_root roots[12];
    storage_config config;
    size_t i;

    assert(base != NULL);
    test_join(home, sizeof(home), base, "home");
    test_make_directory(home);

    test_join(authorized, sizeof(authorized), home, "authorized");
    test_make_directory(authorized);
    test_join(nested, sizeof(nested), authorized, "nested");
    test_make_directory(nested);
    test_join(denied, sizeof(denied), home, "denied");
    test_make_directory(denied);
    test_join(outside, sizeof(outside), base, "outside");
    test_make_directory(outside);

    test_join(path, sizeof(path), authorized, "ok.TXT");
    test_write_file(path);
    test_join(path, sizeof(path), authorized, "no.exe");
    test_write_file(path);
    test_join(path, sizeof(path), authorized, ".txt");
    test_write_file(path);
    test_join(path, sizeof(path), nested, "nested.pdf");
    test_write_file(path);
    test_join(path, sizeof(path), denied, "denied.txt");
    test_write_file(path);
    test_join(path, sizeof(path), outside, "outside.txt");
    test_write_file(path);

    test_join(link_path, sizeof(link_path), authorized, "linked");
    assert(symlink(outside, link_path) == 0);

    assert(setenv("HOME", home, 1) == 0);

    roots[0].path = "authorized";
    roots[0].authorized = true;
    roots[1].path = "denied";
    roots[1].authorized = false;
    roots[2].path = "../outside";
    roots[2].authorized = true;
    roots[3].path = "missing";
    roots[3].authorized = true;

    for (i = 0; i < 8; i++) {
        candidate_dirs[i] = malloc(PATH_MAX);
        assert(candidate_dirs[i] != NULL);
        test_join(candidate_dirs[i], PATH_MAX, home, candidate_names[i]);
        test_make_directory(candidate_dirs[i]);
        test_join(path, sizeof(path), candidate_dirs[i], "candidate.txt");
        test_write_file(path);
        roots[4 + i].path = named_storage_candidates[i];
        roots[4 + i].authorized = (i % 2 == 0);
    }

    config.roots = roots;
    config.root_count = 12;
    config.extensions = extensions;
    config.extension_count = 2;

    assert(scan_storage(&config, &index) == 0);
    test_join(path, sizeof(path), authorized, "ok.TXT");
    assert(index_contains(&index, path));
    test_join(path, sizeof(path), nested, "nested.pdf");
    assert(index_contains(&index, path));
    test_join(path, sizeof(path), authorized, "no.exe");
    assert(!index_contains(&index, path));
    test_join(path, sizeof(path), authorized, ".txt");
    assert(!index_contains(&index, path));
    test_join(path, sizeof(path), denied, "denied.txt");
    assert(!index_contains(&index, path));
    test_join(path, sizeof(path), outside, "outside.txt");
    assert(!index_contains(&index, path));

    for (i = 0; i < 8; i++) {
        test_join(path, sizeof(path), candidate_dirs[i], "candidate.txt");
        assert(index_contains(&index, path) == (i % 2 == 0));
        free(candidate_dirs[i]);
    }

    storage_index_free(&index);

    {
        char absolute_root[PATH_MAX];
        storage_root absolute_configured[] = {
            { absolute_root, true },
            { "authorized/../outside", true }
        };

        memcpy(absolute_root, authorized, strlen(authorized) + 1);
        config.roots = absolute_configured;
        config.root_count = 2;
        assert(scan_storage(&config, &index) == 0);
        test_join(path, sizeof(path), authorized, "ok.TXT");
        assert(index_contains(&index, path));
        test_join(path, sizeof(path), outside, "outside.txt");
        assert(!index_contains(&index, path));
        storage_index_free(&index);
    }

    assert(unlink(link_path) == 0);

    /* An inaccessible root is skipped without blocking other authorized roots. */
    test_join(path, sizeof(path), authorized, "ok.TXT");
    {
        storage_root inaccessible_roots[] = {
            { "/this/path/does/not/exist/for/scan_storage_test", true },
            { authorized, true }
        };
        config.roots = inaccessible_roots;
        config.root_count = 2;
        assert(scan_storage(&config, &index) == 0);
        assert(index_contains(&index, path));
        storage_index_free(&index);
    }

    /* Missing HOME disables relative roots rather than choosing another base. */
    assert(unsetenv("HOME") == 0);
    {
        storage_root relative_root[] = { { "authorized", true } };
        config.roots = relative_root;
        config.root_count = 1;
        assert(scan_storage(&config, &index) == 0);
        assert(index.count == 0);
        storage_index_free(&index);
    }

    {
        char command[PATH_MAX + 32];
        int n = snprintf(command, sizeof(command), "rm -rf -- '%s'", base);
        assert(n >= 0 && (size_t)n < sizeof(command));
        assert(system(command) == 0);
    }
}

int main(void)
{
    test_scan_storage();
    return 0;
}

#endif