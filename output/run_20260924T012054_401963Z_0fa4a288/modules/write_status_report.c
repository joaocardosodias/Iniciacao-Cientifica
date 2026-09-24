#define _GNU_SOURCE
#include <errno.h>
#include <stdbool.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <time.h>
#include <unistd.h>
#include <sys/stat.h>
#include <limits.h>

struct backup_status_summary {
    size_t verified;
    size_t succeeded;
    size_t ignored;
    size_t failed;
};

static void set_report_error(char *error, size_t error_size, const char *operation, int error_number)
{
    if (error == NULL || error_size == 0) {
        return;
    }

    if (error_number != 0) {
        (void)snprintf(error, error_size, "status report %s failed: %s",
                       operation, strerror(error_number));
    } else {
        (void)snprintf(error, error_size, "status report %s failed", operation);
    }
}

/*
 * Writes a report containing only execution metadata and aggregate counts.
 * When enabled is false, this function does not access destination.
 *
 * Returns 0 on success or when disabled; returns -1 on invalid input or I/O
 * failure. Callers should treat report failures independently from the backup
 * processing result.
 */
int write_status_report(bool enabled, const char *destination,
                        const struct backup_status_summary *summary,
                        char *error, size_t error_size)
{
    FILE *stream;
    time_t now;
    struct tm utc_time;
    char timestamp[32];
    const char *state;
    size_t unclassified;
    int write_failed = 0;
    int saved_errno = 0;

    if (error != NULL && error_size > 0) {
        error[0] = '\0';
    }

    if (!enabled) {
        return 0;
    }

    if (destination == NULL || destination[0] == '\0' || summary == NULL) {
        set_report_error(error, error_size, "input validation", EINVAL);
        return -1;
    }

    if (summary->succeeded > summary->verified ||
        summary->ignored > summary->verified ||
        summary->failed > summary->verified ||
        summary->succeeded > summary->verified - summary->ignored ||
        summary->succeeded + summary->ignored > summary->verified ||
        summary->failed > summary->verified - summary->succeeded - summary->ignored) {
        set_report_error(error, error_size, "input validation", EINVAL);
        return -1;
    }

    unclassified = summary->verified - summary->succeeded -
                   summary->ignored - summary->failed;

    now = time(NULL);
    if (now == (time_t)-1 || gmtime_r(&now, &utc_time) == NULL ||
        strftime(timestamp, sizeof(timestamp), "%Y-%m-%dT%H:%M:%SZ", &utc_time) == 0) {
        set_report_error(error, error_size, "timestamp generation", errno);
        return -1;
    }

    if (summary->failed != 0) {
        state = "failure";
    } else if (summary->ignored != 0 || unclassified != 0) {
        state = "partial";
    } else {
        state = "success";
    }

    stream = fopen(destination, "w");
    if (stream == NULL) {
        set_report_error(error, error_size, "open", errno);
        return -1;
    }

    if (fprintf(stream,
                "backup_status_report\n"
                "execution_time_utc=%s\n"
                "state=%s\n"
                "verified=%zu\n"
                "succeeded=%zu\n"
                "ignored=%zu\n"
                "failed=%zu\n"
                "unclassified=%zu\n",
                timestamp, state, summary->verified, summary->succeeded,
                summary->ignored, summary->failed, unclassified) < 0) {
        write_failed = 1;
        saved_errno = errno;
    }

    if (fflush(stream) == EOF) {
        write_failed = 1;
        if (saved_errno == 0) {
            saved_errno = errno;
        }
    }

    if (ferror(stream)) {
        write_failed = 1;
        if (saved_errno == 0) {
            saved_errno = errno != 0 ? errno : EIO;
        }
    }

    if (fclose(stream) == EOF) {
        write_failed = 1;
        if (saved_errno == 0) {
            saved_errno = errno;
        }
    }

    if (write_failed) {
        set_report_error(error, error_size, "write or close", saved_errno);
        return -1;
    }

    return 0;
}

/*
 * Integration helper for a backup flow: report generation is optional and a
 * report I/O failure is recorded without replacing the processing result.
 */
int backup_finish_with_status_report(int processing_result, bool report_enabled,
                                     const char *report_destination,
                                     const struct backup_status_summary *summary)
{
    char error[256];

    if (write_status_report(report_enabled, report_destination, summary,
                            error, sizeof(error)) != 0) {
        (void)fprintf(stderr, "%s\n", error);
    }

    return processing_result;
}

#ifdef STATUS_REPORT_TEST

static int read_file(const char *path, char *buffer, size_t buffer_size)
{
    FILE *stream;
    size_t length;

    if (buffer_size == 0) {
        return -1;
    }

    stream = fopen(path, "r");
    if (stream == NULL) {
        return -1;
    }

    length = fread(buffer, 1, buffer_size - 1, stream);
    if (ferror(stream)) {
        (void)fclose(stream);
        return -1;
    }

    buffer[length] = '\0';
    if (fclose(stream) == EOF) {
        return -1;
    }

    return 0;
}

static int contains_forbidden_content(const char *report)
{
    static const char *const forbidden[] = {
        "payment",
        "bitcoin",
        "operator",
        "contact",
        "extortion",
        "credential",
        "password",
        "private_key",
        "/home/",
        "/root/",
        "personal_data",
        "file_content"
    };
    size_t i;

    for (i = 0; i < sizeof(forbidden) / sizeof(forbidden[0]); ++i) {
        if (strstr(report, forbidden[i]) != NULL) {
            return 1;
        }
    }

    return 0;
}

static int test_enabled_report(const char *directory)
{
    char path[PATH_MAX];
    char report[2048];
    char error[256];
    struct backup_status_summary summary = {
        .verified = 7,
        .succeeded = 3,
        .ignored = 2,
        .failed = 1
    };

    if (snprintf(path, sizeof(path), "%s/enabled.txt", directory) >=
        (int)sizeof(path)) {
        return -1;
    }

    if (write_status_report(true, path, &summary, error, sizeof(error)) != 0) {
        return -1;
    }

    if (read_file(path, report, sizeof(report)) != 0) {
        return -1;
    }

    if (strstr(report, "state=failure\n") == NULL ||
        strstr(report, "verified=7\n") == NULL ||
        strstr(report, "succeeded=3\n") == NULL ||
        strstr(report, "ignored=2\n") == NULL ||
        strstr(report, "failed=1\n") == NULL ||
        strstr(report, "unclassified=1\n") == NULL ||
        strstr(report, "execution_time_utc=") == NULL ||
        contains_forbidden_content(report)) {
        return -1;
    }

    return 0;
}

static int test_disabled_report(const char *directory)
{
    char path[PATH_MAX];
    char buffer[128];
    char error[256];
    struct backup_status_summary summary = {
        .verified = 1,
        .succeeded = 1,
        .ignored = 0,
        .failed = 0
    };
    FILE *stream;

    if (snprintf(path, sizeof(path), "%s/disabled.txt", directory) >=
        (int)sizeof(path)) {
        return -1;
    }

    stream = fopen(path, "w");
    if (stream == NULL) {
        return -1;
    }

    if (fputs("unchanged\n", stream) == EOF || fclose(stream) == EOF) {
        return -1;
    }

    if (write_status_report(false, path, &summary, error, sizeof(error)) != 0) {
        return -1;
    }

    if (read_file(path, buffer, sizeof(buffer)) != 0 ||
        strcmp(buffer, "unchanged\n") != 0) {
        return -1;
    }

    if (snprintf(path, sizeof(path), "%s/not-created.txt", directory) >=
        (int)sizeof(path)) {
        return -1;
    }

    if (write_status_report(false, path, &summary, error, sizeof(error)) != 0) {
        return -1;
    }

    if (access(path, F_OK) == 0 || errno != ENOENT) {
        return -1;
    }

    return 0;
}

static int test_distinct_results(const char *directory)
{
    char path[PATH_MAX];
    char report[2048];
    char error[256];
    struct backup_status_summary summary = {
        .verified = 4,
        .succeeded = 2,
        .ignored = 2,
        .failed = 0
    };

    if (snprintf(path, sizeof(path), "%s/partial.txt", directory) >=
        (int)sizeof(path)) {
        return -1;
    }

    if (write_status_report(true, path, &summary, error, sizeof(error)) != 0 ||
        read_file(path, report, sizeof(report)) != 0 ||
        strstr(report, "state=partial\n") == NULL ||
        strstr(report, "succeeded=2\n") == NULL ||
        strstr(report, "ignored=2\n") == NULL ||
        strstr(report, "failed=0\n") == NULL) {
        return -1;
    }

    summary.verified = 3;
    summary.succeeded = 3;
    summary.ignored = 0;
    summary.failed = 0;

    if (write_status_report(true, path, &summary, error, sizeof(error)) != 0 ||
        read_file(path, report, sizeof(report)) != 0 ||
        strstr(report, "state=success\n") == NULL ||
        strstr(report, "verified=3\n") == NULL) {
        return -1;
    }

    return 0;
}

static int test_io_failures(const char *directory)
{
    char path[PATH_MAX];
    char error[256];
    struct backup_status_summary summary = {
        .verified = 1,
        .succeeded = 1,
        .ignored = 0,
        .failed = 0
    };

    if (snprintf(path, sizeof(path), "%s/missing/report.txt", directory) >=
        (int)sizeof(path)) {
        return -1;
    }

    if (write_status_report(true, path, &summary, error, sizeof(error)) == 0 ||
        error[0] == '\0') {
        return -1;
    }

    if (access("/dev/full", F_OK) == 0) {
        if (write_status_report(true, "/dev/full", &summary,
                                error, sizeof(error)) == 0 ||
            error[0] == '\0') {
            return -1;
        }
    }

    return 0;
}

int main(void)
{
    char template[] = "/tmp/status-report-test-XXXXXX";
    char *directory = mkdtemp(template);
    int result = 1;

    if (directory == NULL) {
        return 1;
    }

    if (test_enabled_report(directory) != 0 ||
        test_disabled_report(directory) != 0 ||
        test_distinct_results(directory) != 0 ||
        test_io_failures(directory) != 0) {
        (void)fprintf(stderr, "status report tests failed\n");
        goto cleanup;
    }

    result = 0;

cleanup:
    {
        char path[PATH_MAX];
        static const char *const files[] = {
            "enabled.txt",
            "disabled.txt",
            "partial.txt",
            "not-created.txt"
        };
        size_t i;

        for (i = 0; i < sizeof(files) / sizeof(files[0]); ++i) {
            if (snprintf(path, sizeof(path), "%s/%s", directory, files[i]) <
                (int)sizeof(path)) {
                (void)unlink(path);
            }
        }

        (void)rmdir(directory);
    }

    return result;
}

#endif