#define _GNU_SOURCE

#include <errno.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

typedef enum {
    VALIDATION_OK = 0,
    VALIDATION_INVALID_ARGUMENT,
    VALIDATION_INVALID_EXTENSION_LIST,
    VALIDATION_INVALID_EXTENSION,
    VALIDATION_INVALID_AUTHORIZED_DIRECTORY,
    VALIDATION_INVALID_SELECTED_DIRECTORY,
    VALIDATION_UNAUTHORIZED_DIRECTORY
} validation_result;

static void validation_set_error(char *error, size_t error_size,
                                 const char *format, ...)
{
    va_list args;

    if (error == NULL || error_size == 0) {
        return;
    }

    va_start(args, format);
    (void)vsnprintf(error, error_size, format, args);
    va_end(args);
}

static int path_has_parent_component(const char *path)
{
    const char *component;

    if (path == NULL) {
        return 0;
    }

    component = path;
    while (*component != '\0') {
        const char *end;

        while (*component == '/') {
            component++;
        }
        if (*component == '\0') {
            break;
        }

        end = component;
        while (*end != '\0' && *end != '/') {
            end++;
        }

        if ((size_t)(end - component) == 2 &&
            component[0] == '.' && component[1] == '.') {
            return 1;
        }

        component = end;
    }

    return 0;
}

/*
 * Extensions use a dot-prefixed, case-sensitive, lowercase ASCII convention.
 * Each suffix segment contains lowercase letters, digits, underscores, or
 * hyphens; dots may separate nonempty segments (for example, ".tar.gz").
 */
static int extension_is_valid(const char *extension)
{
    const unsigned char *p;

    if (extension == NULL || extension[0] != '.' || extension[1] == '\0') {
        return 0;
    }

    p = (const unsigned char *)extension + 1;
    if (*p == '.') {
        return 0;
    }

    for (; *p != '\0'; p++) {
        if (*p == '.') {
            if (p[1] == '\0' || p[1] == '.') {
                return 0;
            }
            continue;
        }

        if (!((*p >= 'a' && *p <= 'z') ||
              (*p >= '0' && *p <= '9') ||
              *p == '_' || *p == '-')) {
            return 0;
        }
    }

    return 1;
}

static int canonical_directory(const char *path, char **canonical)
{
    struct stat st;
    char *resolved;

    *canonical = NULL;

    if (path == NULL || path[0] == '\0' || path_has_parent_component(path)) {
        return 0;
    }

    resolved = realpath(path, NULL);
    if (resolved == NULL) {
        return 0;
    }

    if (stat(resolved, &st) != 0 || !S_ISDIR(st.st_mode)) {
        free(resolved);
        return 0;
    }

    *canonical = resolved;
    return 1;
}

static int path_is_within_directory(const char *directory, const char *path)
{
    size_t directory_length;

    if (directory == NULL || path == NULL) {
        return 0;
    }

    directory_length = strlen(directory);

    if (directory_length == 1 && directory[0] == '/') {
        return path[0] == '/';
    }

    if (strncmp(directory, path, directory_length) != 0) {
        return 0;
    }

    return path[directory_length] == '\0' || path[directory_length] == '/';
}

/*
 * Validate a selected test directory against explicitly configured roots and
 * validate the configured extension list. Paths containing a ".." component
 * are rejected before resolution. realpath() resolves symlinks before the
 * directory-boundary check, so a symlink cannot authorize a path outside a
 * configured root.
 *
 * Extensions must be dot-prefixed, lowercase ASCII suffixes. Comparisons are
 * case-sensitive and the list is not expanded or normalized.
 */
validation_result validate_configuration(
    const char *selected_directory,
    const char *const *authorized_directories,
    size_t authorized_directory_count,
    const char *const *allowed_extensions,
    size_t allowed_extension_count,
    char *error,
    size_t error_size)
{
    char *selected_canonical = NULL;
    size_t i;
    int authorized = 0;

    if (error != NULL && error_size > 0) {
        error[0] = '\0';
    }

    if (selected_directory == NULL || authorized_directories == NULL ||
        allowed_extensions == NULL || authorized_directory_count == 0 ||
        allowed_extension_count == 0) {
        validation_set_error(error, error_size,
                             "Argumentos ou listas de configuração vazios.");
        return VALIDATION_INVALID_ARGUMENT;
    }

    for (i = 0; i < allowed_extension_count; i++) {
        if (allowed_extensions[i] == NULL ||
            allowed_extensions[i][0] == '\0') {
            validation_set_error(error, error_size,
                                 "A lista de extensões contém uma entrada vazia.");
            return VALIDATION_INVALID_EXTENSION_LIST;
        }

        if (!extension_is_valid(allowed_extensions[i])) {
            validation_set_error(error, error_size,
                                 "Extensão inválida: '%s'. Use um sufixo "
                                 "dot-prefixed em minúsculas, sem caminhos "
                                 "ou curingas.",
                                 allowed_extensions[i]);
            return VALIDATION_INVALID_EXTENSION;
        }
    }

    for (i = 0; i < authorized_directory_count; i++) {
        char *authorized_canonical = NULL;

        if (authorized_directories[i] == NULL ||
            authorized_directories[i][0] == '\0' ||
            !canonical_directory(authorized_directories[i],
                                 &authorized_canonical)) {
            validation_set_error(error, error_size,
                                 "Diretório autorizado inválido ou inacessível: '%s'.",
                                 authorized_directories[i] == NULL
                                     ? "(nulo)"
                                     : authorized_directories[i]);
            free(selected_canonical);
            return VALIDATION_INVALID_AUTHORIZED_DIRECTORY;
        }

        if (selected_canonical != NULL &&
            path_is_within_directory(authorized_canonical,
                                     selected_canonical)) {
            authorized = 1;
        }

        free(authorized_canonical);
    }

    if (!canonical_directory(selected_directory, &selected_canonical)) {
        validation_set_error(error, error_size,
                             "Diretório de teste inválido, inexistente, "
                             "não diretório ou contendo traversal: '%s'.",
                             selected_directory);
        return VALIDATION_INVALID_SELECTED_DIRECTORY;
    }

    /*
     * The selected path is canonicalized before comparing it with the
     * authorized roots. Resolve the roots here as well, then compare using
     * directory boundaries rather than plain string prefixes.
     */
    authorized = 0;
    for (i = 0; i < authorized_directory_count; i++) {
        char *authorized_canonical = NULL;

        if (!canonical_directory(authorized_directories[i],
                                 &authorized_canonical)) {
            validation_set_error(error, error_size,
                                 "Diretório autorizado inválido ou inacessível: '%s'.",
                                 authorized_directories[i] == NULL
                                     ? "(nulo)"
                                     : authorized_directories[i]);
            free(selected_canonical);
            return VALIDATION_INVALID_AUTHORIZED_DIRECTORY;
        }

        if (path_is_within_directory(authorized_canonical,
                                     selected_canonical)) {
            authorized = 1;
        }

        free(authorized_canonical);
    }

    if (!authorized) {
        validation_set_error(error, error_size,
                             "O diretório de teste não está dentro de nenhum "
                             "diretório explicitamente autorizado: '%s'.",
                             selected_directory);
        free(selected_canonical);
        return VALIDATION_UNAUTHORIZED_DIRECTORY;
    }

    free(selected_canonical);
    return VALIDATION_OK;
}

#ifdef VALIDATION_TEST_MAIN

#include <fcntl.h>

static void test_write_file(const char *path, const char *contents)
{
    int fd;
    size_t length = strlen(contents);
    size_t written = 0;

    fd = open(path, O_WRONLY | O_CREAT | O_TRUNC, 0600);
    assert(fd >= 0);

    while (written < length) {
        ssize_t result = write(fd, contents + written, length - written);
        assert(result > 0);
        written += (size_t)result;
    }

    assert(close(fd) == 0);
}

static void test_assert_file_unchanged(const char *path,
                                       const struct stat *before,
                                       const char *expected_contents)
{
    struct stat after;
    char buffer[128];
    ssize_t count;
    int fd;

    assert(stat(path, &after) == 0);
    assert(before->st_dev == after.st_dev);
    assert(before->st_ino == after.st_ino);
    assert(before->st_size == after.st_size);
    assert(before->st_mtime == after.st_mtime);
    assert(before->st_ctime == after.st_ctime);

    fd = open(path, O_RDONLY);
    assert(fd >= 0);
    count = read(fd, buffer, sizeof(buffer) - 1);
    assert(count >= 0);
    buffer[count] = '\0';
    assert(close(fd) == 0);
    assert(strcmp(buffer, expected_contents) == 0);
}

static void test_validation(void)
{
    char temporary_root[] = "/tmp/validate-configuration-XXXXXX";
    char allowed[512];
    char allowed_child[512];
    char allowed_sibling[512];
    char outside[512];
    char outside_child[512];
    char escape_link[512];
    char marker[512];
    char error[512];
    const char *authorized[1];
    const char *valid_extensions[] = {".txt", ".c", ".tar.gz"};
    const char *empty_extension[] = {""};
    const char *invalid_extensions[][1] = {
        {"txt"},
        {".TXT"},
        {".*"},
        {".bad/name"},
        {".bad*"},
        {"."},
        {"..bad"},
        {".bad..name"},
        {".bad."}
    };
    struct stat marker_before;
    size_t i;

    assert(mkdtemp(temporary_root) != NULL);

    assert(snprintf(allowed, sizeof(allowed), "%s/allowed", temporary_root) > 0);
    assert(snprintf(allowed_child, sizeof(allowed_child), "%s/child", allowed) > 0);
    assert(snprintf(allowed_sibling, sizeof(allowed_sibling),
                    "%s/allowed-sibling", temporary_root) > 0);
    assert(snprintf(outside, sizeof(outside), "%s/outside", temporary_root) > 0);
    assert(snprintf(outside_child, sizeof(outside_child),
                    "%s/child", outside) > 0);
    assert(snprintf(escape_link, sizeof(escape_link),
                    "%s/escape", allowed) > 0);
    assert(snprintf(marker, sizeof(marker), "%s/marker.txt", allowed_child) > 0);

    assert(mkdir(allowed, 0700) == 0);
    assert(mkdir(allowed_child, 0700) == 0);
    assert(mkdir(allowed_sibling, 0700) == 0);
    assert(mkdir(outside, 0700) == 0);
    assert(mkdir(outside_child, 0700) == 0);
    assert(symlink(outside, escape_link) == 0);
    test_write_file(marker, "validation must not change this file\n");
    assert(stat(marker, &marker_before) == 0);

    authorized[0] = allowed;

    assert(validate_configuration(allowed_child, authorized, 1,
                                  valid_extensions, 3,
                                  error, sizeof(error)) == VALIDATION_OK);

    assert(validate_configuration(allowed, authorized, 1,
                                  valid_extensions, 3,
                                  error, sizeof(error)) == VALIDATION_OK);

    assert(validate_configuration(allowed_sibling, authorized, 1,
                                  valid_extensions, 3,
                                  error, sizeof(error)) ==
           VALIDATION_UNAUTHORIZED_DIRECTORY);
    assert(error[0] != '\0');

    {
        char traversal[1024];
        assert(snprintf(traversal, sizeof(traversal), "%s/../outside/child",
                        allowed) > 0);
        assert(validate_configuration(traversal, authorized, 1,
                                      valid_extensions, 3,
                                      error, sizeof(error)) ==
               VALIDATION_INVALID_SELECTED_DIRECTORY);
        assert(error[0] != '\0');
    }

    {
        char symlink_path[1024];
        assert(snprintf(symlink_path, sizeof(symlink_path), "%s/child",
                        escape_link) > 0);
        assert(validate_configuration(symlink_path, authorized, 1,
                                      valid_extensions, 3,
                                      error, sizeof(error)) ==
               VALIDATION_UNAUTHORIZED_DIRECTORY);
        assert(error[0] != '\0');
    }

    assert(validate_configuration(allowed_child, authorized, 1,
                                  empty_extension, 1,
                                  error, sizeof(error)) ==
           VALIDATION_INVALID_EXTENSION_LIST);
    assert(error[0] != '\0');

    assert(validate_configuration(allowed_child, authorized, 1,
                                  NULL, 0,
                                  error, sizeof(error)) ==
           VALIDATION_INVALID_ARGUMENT);

    for (i = 0; i < sizeof(invalid_extensions) / sizeof(invalid_extensions[0]);
         i++) {
        assert(validate_configuration(allowed_child, authorized, 1,
                                      invalid_extensions[i], 1,
                                      error, sizeof(error)) ==
               VALIDATION_INVALID_EXTENSION);
        assert(error[0] != '\0');
    }

    test_assert_file_unchanged(marker, &marker_before,
                               "validation must not change this file\n");

    assert(unlink(marker) == 0);
    assert(unlink(escape_link) == 0);
    assert(rmdir(allowed_child) == 0);
    assert(rmdir(allowed_sibling) == 0);
    assert(rmdir(outside_child) == 0);
    assert(rmdir(outside) == 0);
    assert(rmdir(allowed) == 0);
    assert(rmdir(temporary_root) == 0);
}

int main(void)
{
    test_validation();
    return 0;
}

#endif