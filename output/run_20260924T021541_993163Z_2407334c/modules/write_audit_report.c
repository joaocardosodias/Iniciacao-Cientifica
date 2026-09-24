#define _GNU_SOURCE
#include <errno.h>
#include <fcntl.h>
#include <limits.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <unistd.h>

struct audit_finding {
    const char *matched_path;
    const char *indicator;
    const char *indicator_value;
};

static int audit_add_size(size_t *total, size_t amount)
{
    if (amount > SIZE_MAX - *total) {
        errno = EOVERFLOW;
        return -1;
    }
    *total += amount;
    return 0;
}

static int audit_json_string_size(const char *value, size_t *result)
{
    size_t length = strlen(value);
    size_t encoded = 2;

    for (size_t i = 0; i < length; ++i) {
        unsigned char ch = (unsigned char)value[i];
        size_t amount = (ch < 0x20) ? 6 : ((ch == '"' || ch == '\\') ? 2 : 1);

        if (audit_add_size(&encoded, amount) < 0)
            return -1;
    }

    *result = encoded;
    return 0;
}

static char *audit_encode_json_string(char *out, const char *value)
{
    static const char hex[] = "0123456789abcdef";

    *out++ = '"';
    for (const unsigned char *p = (const unsigned char *)value; *p; ++p) {
        unsigned char ch = *p;

        if (ch == '"' || ch == '\\') {
            *out++ = '\\';
            *out++ = (char)ch;
        } else if (ch < 0x20) {
            *out++ = '\\';
            *out++ = 'u';
            *out++ = '0';
            *out++ = '0';
            *out++ = hex[ch >> 4];
            *out++ = hex[ch & 0x0f];
        } else {
            *out++ = (char)ch;
        }
    }
    *out++ = '"';
    return out;
}

static int audit_write_all(int fd, const char *data, size_t length)
{
    size_t offset = 0;

    while (offset < length) {
        size_t amount = length - offset;
#ifdef SSIZE_MAX
        if (amount > (size_t)SSIZE_MAX)
            amount = (size_t)SSIZE_MAX;
#endif
        ssize_t written = write(fd, data + offset, amount);
        if (written < 0) {
            if (errno == EINTR)
                continue;
            return -1;
        }
        if (written == 0) {
            errno = EIO;
            return -1;
        }
        offset += (size_t)written;
    }
    return 0;
}

int write_audit_report(
    const char *report_path,
    const struct audit_finding *findings,
    size_t count)
{
    if (report_path == NULL || report_path[0] == '\0' ||
        (count != 0 && findings == NULL)) {
        errno = EINVAL;
        return -1;
    }

    /* A zero count creates or opens the report but writes no records.
       With a nonzero count, every field must be non-NULL; its contents are
       serialized as supplied and the referenced paths are never opened. */
    for (size_t i = 0; i < count; ++i) {
        if (findings[i].matched_path == NULL ||
            findings[i].indicator == NULL ||
            findings[i].indicator_value == NULL) {
            errno = EINVAL;
            return -1;
        }
    }

    int flags = O_WRONLY | O_APPEND | O_CREAT;
#ifdef O_CLOEXEC
    flags |= O_CLOEXEC;
#endif
#ifdef O_NOFOLLOW
    flags |= O_NOFOLLOW;
#endif
#ifdef O_NONBLOCK
    flags |= O_NONBLOCK;
#endif

    int fd = open(report_path, flags, 0600);
    if (fd < 0)
        return -1;

    struct stat st;
    if (fstat(fd, &st) < 0) {
        int saved_errno = errno;
        (void)close(fd);
        errno = saved_errno;
        return -1;
    }
    if (!S_ISREG(st.st_mode)) {
        (void)close(fd);
        errno = EINVAL;
        return -1;
    }

    for (size_t i = 0; i < count; ++i) {
        size_t path_size, indicator_size, value_size;
        if (audit_json_string_size(findings[i].matched_path, &path_size) < 0 ||
            audit_json_string_size(findings[i].indicator, &indicator_size) < 0 ||
            audit_json_string_size(findings[i].indicator_value, &value_size) < 0) {
            int saved_errno = errno;
            (void)close(fd);
            errno = saved_errno;
            return -1;
        }

        size_t total = 0;
        if (audit_add_size(&total, sizeof("{\"matched_path\":") - 1) < 0 ||
            audit_add_size(&total, path_size) < 0 ||
            audit_add_size(&total, sizeof(",\"indicator\":") - 1) < 0 ||
            audit_add_size(&total, indicator_size) < 0 ||
            audit_add_size(&total, sizeof(",\"indicator_value\":") - 1) < 0 ||
            audit_add_size(&total, value_size) < 0 ||
            audit_add_size(&total, sizeof("}\n") - 1) < 0) {
            int saved_errno = errno;
            (void)close(fd);
            errno = saved_errno;
            return -1;
        }

        char *line = malloc(total);
        if (line == NULL) {
            int saved_errno = errno;
            (void)close(fd);
            errno = saved_errno;
            return -1;
        }

        char *cursor = line;
        static const char prefix[] = "{\"matched_path\":";
        static const char middle1[] = ",\"indicator\":";
        static const char middle2[] = ",\"indicator_value\":";
        static const char suffix[] = "}\n";

        memcpy(cursor, prefix, sizeof(prefix) - 1);
        cursor += sizeof(prefix) - 1;
        cursor = audit_encode_json_string(cursor, findings[i].matched_path);
        memcpy(cursor, middle1, sizeof(middle1) - 1);
        cursor += sizeof(middle1) - 1;
        cursor = audit_encode_json_string(cursor, findings[i].indicator);
        memcpy(cursor, middle2, sizeof(middle2) - 1);
        cursor += sizeof(middle2) - 1;
        cursor = audit_encode_json_string(cursor, findings[i].indicator_value);
        memcpy(cursor, suffix, sizeof(suffix) - 1);

        int write_result = audit_write_all(fd, line, total);
        int saved_errno = errno;
        free(line);
        if (write_result < 0) {
            (void)close(fd);
            errno = saved_errno;
            return -1;
        }
    }

    if (close(fd) < 0)
        return -1;
    return 0;
}