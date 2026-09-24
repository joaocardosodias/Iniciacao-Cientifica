#define _GNU_SOURCE
#include <assert.h>
#include <dirent.h>
#include <errno.h>
#include <fcntl.h>
#include <ftw.h>
#include <limits.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>
#include <sys/types.h>
#include <time.h>
#include <unistd.h>

enum epl_processing_location {
    EPL_PROCESSING_LOCATION_UNKNOWN = 0,
    EPL_PROCESSING_LOCATION_LOCAL = 1,
    EPL_PROCESSING_LOCATION_REMOTE = 2
};

enum epl_data_classification {
    EPL_DATA_CLASSIFICATION_UNKNOWN = 0,
    EPL_DATA_CLASSIFICATION_TEST = 1,
    EPL_DATA_CLASSIFICATION_NON_TEST = 2
};

enum epl_key_classification {
    EPL_KEY_CLASSIFICATION_UNKNOWN = 0,
    EPL_KEY_CLASSIFICATION_TEST = 1,
    EPL_KEY_CLASSIFICATION_NON_TEST = 2
};

enum epl_key_storage_location {
    EPL_KEY_STORAGE_UNKNOWN = 0,
    EPL_KEY_STORAGE_LOCAL = 1,
    EPL_KEY_STORAGE_NONLOCAL = 2
};

struct epl_request {
    enum epl_processing_location processing_location;
    enum epl_data_classification data_classification;
    enum epl_key_classification key_classification;
    enum epl_key_storage_location key_storage_location;
    int encryption_requested;
    int transmits_file_contents;
    int transmits_cryptographic_material;
};

typedef int (*epl_local_processing_callback)(void *context);

enum validation_result {
    VALIDATION_OK = 0,
    VALIDATION_INVALID_ARGUMENT,
    VALIDATION_CRONTAB_MODIFICATION_FORBIDDEN,
    VALIDATION_AUTOMATIC_EXECUTION_FORBIDDEN
};

struct deployment_options {
    const char *execution_mode;
    int modify_system_crontab;
    int enable_automatic_execution;
    int use_cron;
    int use_systemd_timer;
    int use_scheduled_task;
    int run_on_boot;
    int run_on_login;
};

struct backup_status_summary {
    size_t verified;
    size_t succeeded;
    size_t ignored;
    size_t failed;
};

extern int validate_scope(const char *configured_scope,
                          char *resolved_path, size_t resolved_path_size,
                          char *error, size_t error_size);
extern int scan_storage(const char *configured_test_dir);
extern int preserve_sources(const char *const sources[],
                            const char *const destinations[], size_t count);
extern int enforce_local_processing(const struct epl_request *request);
extern int run_local_processing(const struct epl_request *request,
                                epl_local_processing_callback callback,
                                void *context);
extern enum validation_result
validate_execution_mode(const struct deployment_options *options,
                        char *error_message, size_t error_message_size);
extern int write_status_report(bool enabled, const char *destination,
                               const struct backup_status_summary *summary,
                               char *error, size_t error_size);
extern int backup_finish_with_status_report(
    int processing_result, bool report_enabled, const char *report_destination,
    const struct backup_status_summary *summary);

static int local_processing(void *context)
{
    (void)context;
    return 0;
}

int main(int argc, char *argv[])
{
    char resolved_path[PATH_MAX];
    char error[256];
    char validation_error[256];
    const char *sources[1];
    const char *destinations[1];
    struct epl_request request = {
        .processing_location = EPL_PROCESSING_LOCATION_LOCAL,
        .data_classification = EPL_DATA_CLASSIFICATION_UNKNOWN,
        .key_classification = EPL_KEY_CLASSIFICATION_UNKNOWN,
        .key_storage_location = EPL_KEY_STORAGE_UNKNOWN,
        .encryption_requested = 0,
        .transmits_file_contents = 0,
        .transmits_cryptographic_material = 0
    };
    struct deployment_options options = {
        .execution_mode = "manual",
        .modify_system_crontab = 0,
        .enable_automatic_execution = 0,
        .use_cron = 0,
        .use_systemd_timer = 0,
        .use_scheduled_task = 0,
        .run_on_boot = 0,
        .run_on_login = 0
    };
    struct backup_status_summary summary = {
        .verified = 0,
        .succeeded = 0,
        .ignored = 0,
        .failed = 0
    };
    const char *path;
    int processing_result;

    (void)argc;
    path = argv[0] != NULL ? argv[0] : "";

    (void)validate_scope(path, resolved_path, sizeof(resolved_path),
                         error, sizeof(error));
    (void)scan_storage(path);

    sources[0] = path;
    destinations[0] = path;
    (void)preserve_sources(sources, destinations, 0);

    processing_result = enforce_local_processing(&request);
    if (processing_result == 0) {
        processing_result = run_local_processing(&request, local_processing,
                                                 NULL);
    }

    (void)validate_execution_mode(&options, validation_error,
                                  sizeof(validation_error));
    (void)write_status_report(false, path, &summary, error, sizeof(error));
    return backup_finish_with_status_report(processing_result, false, path,
                                            &summary);
}
