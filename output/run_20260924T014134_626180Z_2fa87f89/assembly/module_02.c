#define _GNU_SOURCE
#include <ctype.h>
#include <stddef.h>
#include <string.h>

typedef struct {
    const char *value;
    const void *provenance;
} configuration_value;

typedef int (*configuration_source_authorizer)(
    void *context,
    const char *key,
    const configuration_value *value);

typedef int (*configuration_schedule_validator)(
    void *context,
    const char *schedule);

typedef struct {
    configuration_value endpoint;
    configuration_value payment_value;
    configuration_value schedule;
    int schedule_required;
} payment_configuration;

typedef struct {
    void *context;
    configuration_source_authorizer source_is_approved;
    configuration_schedule_validator schedule_is_approved;
} configuration_validation_policy;

typedef enum {
    CONFIGURATION_VALID = 0,
    CONFIGURATION_INVALID_ARGUMENT,
    CONFIGURATION_MISSING_REQUIRED_VALUE,
    CONFIGURATION_INVALID_VALUE,
    CONFIGURATION_UNAPPROVED_SOURCE,
    CONFIGURATION_UNAPPROVED_SCHEDULE
} configuration_validation_result;

/*
 * The repository integration must supply source_is_approved using the
 * project's existing deployment/secrets provenance APIs. It must verify that
 * the provenance belongs to this exact loaded value and reject defaults,
 * embedded values, and unauthorized files or sources. The validator does
 * not define or assume which sources are approved.
 *
 * The repository integration must supply schedule_is_approved using the
 * project's existing corporate schedule rules. No schedule syntax or default
 * is prescribed here.
 *
 * Neither callback should log values: configuration values may be sensitive.
 */
static int
configuration_value_has_content(const configuration_value *value)
{
    const unsigned char *p;

    if (value == NULL || value->value == NULL || value->provenance == NULL)
        return 0;

    p = (const unsigned char *)value->value;
    while (*p != '\0') {
        if (!isspace(*p))
            return 1;
        ++p;
    }
    return 0;
}

static int
configuration_source_is_approved(
    const configuration_validation_policy *policy,
    const char *key,
    const configuration_value *value)
{
    if (policy == NULL || policy->source_is_approved == NULL ||
        key == NULL || value == NULL)
        return 0;

    return policy->source_is_approved(policy->context, key, value) == 1;
}

configuration_validation_result
validate_configuration(
    const payment_configuration *configuration,
    const configuration_validation_policy *policy)
{
    if (configuration == NULL || policy == NULL ||
        policy->source_is_approved == NULL ||
        (configuration->schedule_required != 0 &&
         configuration->schedule_required != 1))
        return CONFIGURATION_INVALID_ARGUMENT;

    if (!configuration_value_has_content(&configuration->endpoint) ||
        !configuration_value_has_content(&configuration->payment_value))
        return CONFIGURATION_MISSING_REQUIRED_VALUE;

    if (!configuration_source_is_approved(
            policy, "endpoint", &configuration->endpoint) ||
        !configuration_source_is_approved(
            policy, "payment_value", &configuration->payment_value))
        return CONFIGURATION_UNAPPROVED_SOURCE;

    if (configuration->schedule.value == NULL) {
        if (configuration->schedule_required)
            return CONFIGURATION_MISSING_REQUIRED_VALUE;
        return CONFIGURATION_VALID;
    }

    if (!configuration_value_has_content(&configuration->schedule))
        return CONFIGURATION_INVALID_VALUE;

    if (!configuration_source_is_approved(
            policy, "schedule", &configuration->schedule))
        return CONFIGURATION_UNAPPROVED_SOURCE;

    if (policy->schedule_is_approved == NULL ||
        policy->schedule_is_approved(
            policy->context, configuration->schedule.value) != 1)
        return CONFIGURATION_UNAPPROVED_SCHEDULE;

    return CONFIGURATION_VALID;
}

#ifdef VALIDATE_CONFIGURATION_TEST

#include <assert.h>

enum fixture_origin {
    FIXTURE_DEPLOYMENT,
    FIXTURE_SECRET_STORE,
    FIXTURE_EMBEDDED,
    FIXTURE_UNAUTHORIZED_FILE,
    FIXTURE_LOAD_FAILURE
};

static const enum fixture_origin endpoint_origin = FIXTURE_DEPLOYMENT;
static const enum fixture_origin payment_origin = FIXTURE_SECRET_STORE;
static const enum fixture_origin schedule_origin = FIXTURE_DEPLOYMENT;
static const enum fixture_origin embedded_origin = FIXTURE_EMBEDDED;
static const enum fixture_origin unauthorized_origin = FIXTURE_UNAUTHORIZED_FILE;
static const enum fixture_origin load_failure_origin = FIXTURE_LOAD_FAILURE;

static int
fixture_source_authorizer(
    void *context,
    const char *key,
    const configuration_value *value)
{
    (void)context;

    if (key == NULL || value == NULL || value->value == NULL ||
        value->provenance == NULL)
        return 0;

    if (strcmp(key, "endpoint") == 0)
        return value->provenance == &endpoint_origin;
    if (strcmp(key, "payment_value") == 0)
        return value->provenance == &payment_origin;
    if (strcmp(key, "schedule") == 0)
        return value->provenance == &schedule_origin;

    return 0;
}

static int
fixture_schedule_validator(void *context, const char *schedule)
{
    (void)context;

    /*
     * A test fixture only. Production must use the project's existing
     * approved schedule validator rather than this fixture value.
     */
    return schedule != NULL && strcmp(schedule, "fixture-approved-schedule") == 0;
}

static payment_configuration
fixture_configuration(void)
{
    payment_configuration configuration = {
        .endpoint = {
            .value = "fixture-endpoint",
            .provenance = &endpoint_origin
        },
        .payment_value = {
            .value = "fixture-payment-value",
            .provenance = &payment_origin
        },
        .schedule = {
            .value = "fixture-approved-schedule",
            .provenance = &schedule_origin
        },
        .schedule_required = 1
    };

    return configuration;
}

int
main(void)
{
    configuration_validation_policy policy = {
        .context = NULL,
        .source_is_approved = fixture_source_authorizer,
        .schedule_is_approved = fixture_schedule_validator
    };
    payment_configuration configuration = fixture_configuration();

    assert(validate_configuration(&configuration, &policy) ==
           CONFIGURATION_VALID);

    configuration.endpoint.provenance = &embedded_origin;
    assert(validate_configuration(&configuration, &policy) ==
           CONFIGURATION_UNAPPROVED_SOURCE);

    configuration = fixture_configuration();
    configuration.payment_value.provenance = &unauthorized_origin;
    assert(validate_configuration(&configuration, &policy) ==
           CONFIGURATION_UNAPPROVED_SOURCE);

    configuration = fixture_configuration();
    configuration.schedule.value = "fixture-unapproved-schedule";
    assert(validate_configuration(&configuration, &policy) ==
           CONFIGURATION_UNAPPROVED_SCHEDULE);

    configuration = fixture_configuration();
    configuration.schedule.provenance = &unauthorized_origin;
    assert(validate_configuration(&configuration, &policy) ==
           CONFIGURATION_UNAPPROVED_SOURCE);

    configuration = fixture_configuration();
    configuration.schedule.value = NULL;
    configuration.schedule.provenance = NULL;
    assert(validate_configuration(&configuration, &policy) ==
           CONFIGURATION_MISSING_REQUIRED_VALUE);

    configuration = fixture_configuration();
    configuration.endpoint.value = " \t\n";
    assert(validate_configuration(&configuration, &policy) ==
           CONFIGURATION_MISSING_REQUIRED_VALUE);

    configuration = fixture_configuration();
    configuration.payment_value.value = NULL;
    assert(validate_configuration(&configuration, &policy) ==
           CONFIGURATION_MISSING_REQUIRED_VALUE);

    configuration = fixture_configuration();
    configuration.schedule.value = " \t";
    assert(validate_configuration(&configuration, &policy) ==
           CONFIGURATION_INVALID_VALUE);

    configuration = fixture_configuration();
    configuration.endpoint.provenance = &load_failure_origin;
    assert(validate_configuration(&configuration, &policy) ==
           CONFIGURATION_UNAPPROVED_SOURCE);

    configuration = fixture_configuration();
    configuration.schedule_required = 2;
    assert(validate_configuration(&configuration, &policy) ==
           CONFIGURATION_INVALID_ARGUMENT);

    assert(validate_configuration(NULL, &policy) ==
           CONFIGURATION_INVALID_ARGUMENT);

    policy.source_is_approved = NULL;
    configuration = fixture_configuration();
    assert(validate_configuration(&configuration, &policy) ==
           CONFIGURATION_INVALID_ARGUMENT);

    return 0;
}

#endif