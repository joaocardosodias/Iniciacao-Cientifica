#define _GNU_SOURCE
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <inttypes.h>
#include <limits.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <strings.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <unistd.h>

#define EAT_MAX_DEPTH 128
#define EAT_MARKER_SUFFIX ".PROCESSED"

typedef struct {
    char *buffer;
    size_t capacity;
    size_t length;
    int errors;
    int overflow;
    int simulation;
} eat_context;

static int eat_reportf(eat_context *context, const char *format, ...)
{
    va_list arguments;
    int written;

    if (context->overflow || context->capacity == 0)
        return -1;

    va_start(arguments, format);
    written = vsnprintf(context->buffer + context->length,
                        context->capacity - context->length,
                        format, arguments);
    va_end(arguments);

    if (written < 0 || (size_t)written >= context->capacity - context->length) {
        context->overflow = 1;
        context->errors++;
        if (context->capacity != 0)
            context->buffer[context->capacity - 1] = '\0';
        return -1;
    }

    context->length += (size_t)written;
    return 0;
}

static void eat_report_escaped(eat_context *context, const char *text)
{
    const unsigned char *cursor = (const unsigned char *)text;

    while (*cursor != '\0' && !context->overflow) {
        if (*cursor == '\\' || *cursor == '"') {
            eat_reportf(context, "\\%c", (int)*cursor);
        } else if (*cursor < 32 || *cursor >= 127) {
            eat_reportf(context, "\\x%02x", (unsigned int)*cursor);
        } else {
            eat_reportf(context, "%c", (int)*cursor);
        }
        cursor++;
    }
}

static void eat_report_error(eat_context *context, const char *relative_path,
                             const char *operation, int error_number)
{
    context->errors++;
    if (context->overflow)
        return;

    eat_reportf(context, "ERROR operation=%s errno=%d path=\"",
                operation, error_number);
    eat_report_escaped(context, relative_path != NULL ? relative_path : "");
    eat_reportf(context, "\"\n");
}

static int eat_is_unexpected_name(const char *name)
{
    const unsigned char *cursor = (const unsigned char *)name;

    while (*cursor != '\0') {
        if (*cursor < 32 || *cursor == 127)
            return 1;
        cursor++;
    }
    return 0;
}

static int eat_recognized_extension(const char *name, const char **extension,
                                    int *is_backup)
{
    static const char *const extensions[] = {
        ".xlsx", ".docx", ".pdf", ".txt", ".csv", ".jpg", ".png",
        ".db", ".backup", ".psd", ".zip", ".rar", ".bak", ".old"
    };
    const char *dot;
    size_t index;

    dot = strrchr(name, '.');
    if (dot == NULL)
        return 0;

    for (index = 0; index < sizeof(extensions) / sizeof(extensions[0]); index++) {
        if (strcasecmp(dot, extensions[index]) == 0) {
            *extension = extensions[index];
            *is_backup = (strcasecmp(dot, ".bak") == 0 ||
                          strcasecmp(dot, ".backup") == 0 ||
                          strcasecmp(dot, ".old") == 0);
            return 1;
        }
    }
    return 0;
}

static char *eat_join_relative(const char *parent, const char *name)
{
    size_t parent_length = strlen(parent);
    size_t name_length = strlen(name);
    size_t total;
    char *result;

    if (parent_length > SIZE_MAX - name_length - 2)
        return NULL;

    total = parent_length + name_length + (parent_length != 0 ? 2 : 1);
    result = malloc(total);
    if (result == NULL)
        return NULL;

    if (parent_length != 0) {
        memcpy(result, parent, parent_length);
        result[parent_length] = '/';
        memcpy(result + parent_length + 1, name, name_length + 1);
    } else {
        memcpy(result, name, name_length + 1);
    }

    return result;
}

static void eat_write_marker(eat_context *context, int directory_fd,
                             const char *name, const char *relative_path,
                             off_t file_size, const char *extension)
{
    size_t name_length = strlen(name);
    size_t suffix_length = sizeof(EAT_MARKER_SUFFIX) - 1;
    char *marker_name;
    int marker_fd;
    char contents[256];
    int contents_length;
    size_t offset = 0;

    if (name_length > SIZE_MAX - suffix_length - 1) {
        eat_report_error(context, relative_path, "marker_name_too_long", EOVERFLOW);
        return;
    }

    marker_name = malloc(name_length + suffix_length + 1);
    if (marker_name == NULL) {
        eat_report_error(context, relative_path, "allocate_marker_name", ENOMEM);
        return;
    }

    memcpy(marker_name, name, name_length);
    memcpy(marker_name + name_length, EAT_MARKER_SUFFIX, suffix_length + 1);

    marker_fd = openat(directory_fd, marker_name,
                       O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW,
                       S_IRUSR | S_IWUSR);
    if (marker_fd < 0) {
        int saved_errno = errno;
        eat_report_error(context, relative_path, "create_marker", saved_errno);
        free(marker_name);
        return;
    }

    contents_length = snprintf(contents, sizeof(contents),
                               "demo_marker=1\nsource_size=%ju\nextension=%s\n",
                               (uintmax_t)file_size, extension);
    if (contents_length < 0 || (size_t)contents_length >= sizeof(contents)) {
        eat_report_error(context, relative_path, "format_marker", EOVERFLOW);
        close(marker_fd);
        free(marker_name);
        return;
    }

    while (offset < (size_t)contents_length) {
        ssize_t written = write(marker_fd, contents + offset,
                                (size_t)contents_length - offset);
        if (written < 0 && errno == EINTR)
            continue;
        if (written <= 0) {
            int saved_errno = written < 0 ? errno : EIO;
            eat_report_error(context, relative_path, "write_marker", saved_errno);
            break;
        }
        offset += (size_t)written;
    }

    if (close(marker_fd) < 0)
        eat_report_error(context, relative_path, "close_marker", errno);

    if (offset == (size_t)contents_length && !context->overflow) {
        eat_reportf(context, "MARKER path=\"");
        eat_report_escaped(context, relative_path);
        eat_reportf(context, "%s\"\n", EAT_MARKER_SUFFIX);
    }

    free(marker_name);
}

static void eat_scan_directory(eat_context *context, int directory_fd,
                               const char *relative_directory, unsigned int depth)
{
    DIR *directory;
    struct dirent *entry;
    int stream_fd = directory_fd;

    directory = fdopendir(stream_fd);
    if (directory == NULL) {
        int saved_errno = errno;
        close(stream_fd);
        eat_report_error(context, relative_directory, "fdopendir", saved_errno);
        return;
    }

    for (;;) {
        struct stat status;
        char *relative_path;
        int stat_result;
        int saved_errno;

        errno = 0;
        entry = readdir(directory);
        if (entry == NULL) {
            saved_errno = errno;
            if (saved_errno != 0)
                eat_report_error(context, relative_directory, "readdir", saved_errno);
            break;
        }

        if (strcmp(entry->d_name, ".") == 0 || strcmp(entry->d_name, "..") == 0)
            continue;

        relative_path = eat_join_relative(relative_directory, entry->d_name);
        if (relative_path == NULL) {
            eat_report_error(context, relative_directory, "allocate_path", ENOMEM);
            continue;
        }

        if (eat_is_unexpected_name(entry->d_name)) {
            context->errors++;
            eat_reportf(context, "WARNING unexpected_filename path=\"");
            eat_report_escaped(context, relative_path);
            eat_reportf(context, "\"\n");
        }

        stat_result = fstatat(dirfd(directory), entry->d_name, &status,
                              AT_SYMLINK_NOFOLLOW);
        if (stat_result < 0) {
            saved_errno = errno;
            eat_report_error(context, relative_path, "fstatat", saved_errno);
            free(relative_path);
            continue;
        }

        if (S_ISDIR(status.st_mode)) {
            int child_fd;

            if (depth >= EAT_MAX_DEPTH) {
                eat_report_error(context, relative_path, "maximum_depth",
                                 ELOOP);
                free(relative_path);
                continue;
            }

            child_fd = openat(dirfd(directory), entry->d_name,
                              O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
            if (child_fd < 0) {
                saved_errno = errno;
                eat_report_error(context, relative_path, "open_directory",
                                 saved_errno);
                free(relative_path);
                continue;
            }

            {
                struct stat opened_status;
                if (fstat(child_fd, &opened_status) < 0 ||
                    !S_ISDIR(opened_status.st_mode)) {
                    saved_errno = errno != 0 ? errno : ENOTDIR;
                    close(child_fd);
                    eat_report_error(context, relative_path,
                                     "verify_directory", saved_errno);
                    free(relative_path);
                    continue;
                }
            }

            eat_scan_directory(context, child_fd, relative_path, depth + 1);
            free(relative_path);
            continue;
        }

        if (S_ISREG(status.st_mode)) {
            const char *extension = NULL;
            int is_backup = 0;

            if (eat_recognized_extension(entry->d_name, &extension, &is_backup)) {
                eat_reportf(context, "FILE category=%s size=%ju extension=%s path=\"",
                            is_backup ? "backup" : "recognized",
                            (uintmax_t)status.st_size, extension);
                eat_report_escaped(context, relative_path);
                eat_reportf(context, "\"\n");

                if (context->simulation)
                    eat_write_marker(context, dirfd(directory), entry->d_name,
                                     relative_path, status.st_size, extension);
            }
        }

        free(relative_path);
    }

    if (closedir(directory) < 0)
        eat_report_error(context, relative_directory, "closedir", errno);
}

static int eat_open_canonical_target(const char *canonical_root,
                                     const char *canonical_target)
{
    const char *relative_target;
    char *components;
    char *save_pointer = NULL;
    char *component;
    int current_fd;

    if (strcmp(canonical_root, "/") == 0) {
        if (canonical_target[0] != '/' || canonical_target[1] == '\0')
            return -1;
        relative_target = canonical_target + 1;
    } else {
        size_t root_length = strlen(canonical_root);
        if (strncmp(canonical_target, canonical_root, root_length) != 0 ||
            canonical_target[root_length] != '/' ||
            canonical_target[root_length + 1] == '\0')
            return -1;
        relative_target = canonical_target + root_length + 1;
    }

    current_fd = open(canonical_root,
                      O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
    if (current_fd < 0)
        return -1;

    components = strdup(relative_target);
    if (components == NULL) {
        close(current_fd);
        errno = ENOMEM;
        return -1;
    }

    component = strtok_r(components, "/", &save_pointer);
    while (component != NULL) {
        int next_fd = openat(current_fd, component,
                             O_RDONLY | O_DIRECTORY | O_CLOEXEC | O_NOFOLLOW);
        if (next_fd < 0) {
            int saved_errno = errno;
            close(current_fd);
            free(components);
            errno = saved_errno;
            return -1;
        }
        close(current_fd);
        current_fd = next_fd;
        component = strtok_r(NULL, "/", &save_pointer);
    }

    free(components);
    return current_fd;
}

 
int enumeracao_e_transformacao_de_arquivos(const char *dedicated_temp_area,
                                            const char *test_directory,
                                            int simulation,
                                            char *report_buffer,
                                            size_t report_capacity)
{
    eat_context context;
    char *canonical_root = NULL;
    char *canonical_target = NULL;
    struct stat root_status;
    struct stat target_status;
    int target_fd = -1;
    int saved_errno;

    if (report_buffer == NULL || report_capacity == 0)
        return -1;

    report_buffer[0] = '\0';
    memset(&context, 0, sizeof(context));
    context.buffer = report_buffer;
    context.capacity = report_capacity;
    context.simulation = simulation != 0;

    if (dedicated_temp_area == NULL || test_directory == NULL ||
        dedicated_temp_area[0] == '\0' || test_directory[0] == '\0') {
        eat_report_error(&context, "", "invalid_path_argument", EINVAL);
        return -1;
    }

    canonical_root = realpath(dedicated_temp_area, NULL);
    if (canonical_root == NULL) {
        saved_errno = errno;
        eat_report_error(&context, "", "canonicalize_sandbox", saved_errno);
        return -1;
    }

    canonical_target = realpath(test_directory, NULL);
    if (canonical_target == NULL) {
        saved_errno = errno;
        eat_report_error(&context, "", "canonicalize_test_directory",
                         saved_errno);
        free(canonical_root);
        return -1;
    }

    if (stat(canonical_root, &root_status) < 0 ||
        !S_ISDIR(root_status.st_mode)) {
        saved_errno = errno != 0 ? errno : ENOTDIR;
        eat_report_error(&context, "", "validate_sandbox", saved_errno);
        free(canonical_root);
        free(canonical_target);
        return -1;
    }

    if (stat(canonical_target, &target_status) < 0 ||
        !S_ISDIR(target_status.st_mode)) {
        saved_errno = errno != 0 ? errno : ENOTDIR;
        eat_report_error(&context, "", "validate_test_directory", saved_errno);
        free(canonical_root);
        free(canonical_target);
        return -1;
    }

    target_fd = eat_open_canonical_target(canonical_root, canonical_target);
    if (target_fd < 0) {
        saved_errno = errno != 0 ? errno : EPERM;
        eat_report_error(&context, "", "validate_sandbox_containment",
                         saved_errno);
        free(canonical_root);
        free(canonical_target);
        return -1;
    }

    eat_reportf(&context, "SCAN simulation=%d\n", context.simulation);
    eat_scan_directory(&context, target_fd, "", 0);

    free(canonical_root);
    free(canonical_target);
    return context.errors == 0 ? 0 : -1;
}