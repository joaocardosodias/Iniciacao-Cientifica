#define _GNU_SOURCE

#include <assert.h>
#include <stddef.h>
#include <stdio.h>
#include <string.h>

/*
 * Assumption: the project does not provide deployment-option types or an
 * established error convention. This standalone API accepts explicit flags
 * for each supported automatic-execution mechanism and fails closed for
 * missing, unknown, or malformed options.
 */

enum validation_result {
    VALIDATION_OK = 0,
    VALIDATION_INVALID_ARGUMENT,
    VALIDATION_CRONTAB_MODIFICATION_FORBIDDEN,
    VALIDATION_AUTOMATIC_EXECUTION_FORBIDDEN
};

struct deployment_options {
    const char *execution_mode; /* Must be exactly "manual". */
    int modify_system_crontab;
    int enable_automatic_execution;
    int use_cron;
    int use_systemd_timer;
    int use_scheduled_task;
    int run_on_boot;
    int run_on_login;
};

/*
 * Returns VALIDATION_OK only for an explicitly manual deployment with no
 * requested system crontab changes or automatic-execution mechanisms.
 * On failure, returns a stable error code and, when provided, writes a brief
 * message to error_message. This function performs validation only.
 */
enum validation_result
validate_execution_mode(const struct deployment_options *options,
                        char *error_message,
                        size_t error_message_size)
{
    const int *flags;
    size_t i;
    static const char invalid_message[] =
        "Invalid or missing deployment execution options.";
    static const char crontab_message[] =
        "System crontab modification is not permitted.";
    static const char automatic_message[] =
        "Automatic execution is not permitted; select manual execution.";

    if (error_message != NULL && error_message_size > 0)
        error_message[0] = '\0';

    if (options == NULL || options->execution_mode == NULL ||
        options->execution_mode[0] == '\0') {
        if (error_message != NULL && error_message_size > 0)
            snprintf(error_message, error_message_size, "%s", invalid_message);
        return VALIDATION_INVALID_ARGUMENT;
    }

    flags = &options->modify_system_crontab;
    for (i = 0; i < 7; ++i) {
        if (flags[i] != 0 && flags[i] != 1) {
            if (error_message != NULL && error_message_size > 0)
                snprintf(error_message, error_message_size, "%s",
                         invalid_message);
            return VALIDATION_INVALID_ARGUMENT;
        }
    }

    if (strcmp(options->execution_mode, "manual") != 0) {
        if (strcmp(options->execution_mode, "automatic") == 0) {
            if (error_message != NULL && error_message_size > 0)
                snprintf(error_message, error_message_size, "%s",
                         automatic_message);
            return VALIDATION_AUTOMATIC_EXECUTION_FORBIDDEN;
        }

        if (error_message != NULL && error_message_size > 0)
            snprintf(error_message, error_message_size, "%s", invalid_message);
        return VALIDATION_INVALID_ARGUMENT;
    }

    if (options->modify_system_crontab) {
        if (error_message != NULL && error_message_size > 0)
            snprintf(error_message, error_message_size, "%s", crontab_message);
        return VALIDATION_CRONTAB_MODIFICATION_FORBIDDEN;
    }

    if (options->enable_automatic_execution ||
        options->use_cron ||
        options->use_systemd_timer ||
        options->use_scheduled_task ||
        options->run_on_boot ||
        options->run_on_login) {
        if (error_message != NULL && error_message_size > 0)
            snprintf(error_message, error_message_size, "%s",
                     automatic_message);
        return VALIDATION_AUTOMATIC_EXECUTION_FORBIDDEN;
    }

    return VALIDATION_OK;
}

static struct deployment_options
manual_options(void)
{
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

    return options;
}

static void
test_manual_execution_is_allowed(void)
{
    struct deployment_options options = manual_options();
    char error[128];

    assert(validate_execution_mode(&options, error, sizeof(error)) ==
           VALIDATION_OK);
    assert(error[0] == '\0');
}

static void
test_system_crontab_modification_is_rejected(void)
{
    struct deployment_options options = manual_options();
    char error[128];

    options.modify_system_crontab = 1;
    assert(validate_execution_mode(&options, error, sizeof(error)) ==
           VALIDATION_CRONTAB_MODIFICATION_FORBIDDEN);
    assert(error[0] != '\0');
}

static void
test_automatic_execution_is_rejected(void)
{
    struct deployment_options options = manual_options();
    char error[128];

    options.execution_mode = "automatic";
    assert(validate_execution_mode(&options, error, sizeof(error)) ==
           VALIDATION_AUTOMATIC_EXECUTION_FORBIDDEN);
    assert(error[0] != '\0');

    options = manual_options();
    options.enable_automatic_execution = 1;
    assert(validate_execution_mode(&options, error, sizeof(error)) ==
           VALIDATION_AUTOMATIC_EXECUTION_FORBIDDEN);

    options = manual_options();
    options.use_cron = 1;
    assert(validate_execution_mode(&options, error, sizeof(error)) ==
           VALIDATION_AUTOMATIC_EXECUTION_FORBIDDEN);

    options = manual_options();
    options.use_systemd_timer = 1;
    assert(validate_execution_mode(&options, error, sizeof(error)) ==
           VALIDATION_AUTOMATIC_EXECUTION_FORBIDDEN);

    options = manual_options();
    options.use_scheduled_task = 1;
    assert(validate_execution_mode(&options, error, sizeof(error)) ==
           VALIDATION_AUTOMATIC_EXECUTION_FORBIDDEN);

    options = manual_options();
    options.run_on_boot = 1;
    assert(validate_execution_mode(&options, error, sizeof(error)) ==
           VALIDATION_AUTOMATIC_EXECUTION_FORBIDDEN);

    options = manual_options();
    options.run_on_login = 1;
    assert(validate_execution_mode(&options, error, sizeof(error)) ==
           VALIDATION_AUTOMATIC_EXECUTION_FORBIDDEN);
}

static void
test_invalid_or_missing_options_are_rejected(void)
{
    struct deployment_options options = manual_options();
    char error[128];

    assert(validate_execution_mode(NULL, error, sizeof(error)) ==
           VALIDATION_INVALID_ARGUMENT);
    assert(error[0] != '\0');

    options.execution_mode = NULL;
    assert(validate_execution_mode(&options, error, sizeof(error)) ==
           VALIDATION_INVALID_ARGUMENT);

    options.execution_mode = "";
    assert(validate_execution_mode(&options, error, sizeof(error)) ==
           VALIDATION_INVALID_ARGUMENT);

    options.execution_mode = "manual-ish";
    assert(validate_execution_mode(&options, error, sizeof(error)) ==
           VALIDATION_INVALID_ARGUMENT);

    options = manual_options();
    options.use_cron = 2;
    assert(validate_execution_mode(&options, error, sizeof(error)) ==
           VALIDATION_INVALID_ARGUMENT);
}

int
main(void)
{
    test_manual_execution_is_allowed();
    test_system_crontab_modification_is_rejected();
    test_automatic_execution_is_rejected();
    test_invalid_or_missing_options_are_rejected();

    puts("All validate_execution_mode tests passed.");
    return 0;
}