#define _GNU_SOURCE
#include <stdatomic.h>
#include <stddef.h>
#include <string.h>

/*
 * Safe-operation policy interface.
 *
 * Call enforce_safe_policy() in place of invoking the operation directly.
 * It validates the request, asks the project's authorization mechanism, audits
 * the decision using action and result codes only, and invokes the operation
 * only after authorization and successful auditing.
 *
 * The authorization callback must verify explicit authorization for the exact
 * action and affected resources. It receives the full request; audit callbacks
 * do not receive resource names, destinations, authorization data, or payloads.
 *
 * A process-wide atomic gate serializes policy checks and their corresponding
 * executions. This limits races between callers using this interface; callers
 * must also use the project's resource locking or transactional mechanisms to
 * protect against changes made outside this interface. Callbacks must not
 * recursively call enforce_safe_policy().
 *
 * Integrate the result values with the project's established error codes at
 * the call site if it uses a different result convention. The operation's
 * exact return code is preserved in operation_status.
 */
enum safe_policy_action {
    SAFE_POLICY_ACTION_INVALID = 0,
    SAFE_POLICY_ACTION_OTHER,
    SAFE_POLICY_ACTION_CRONTAB_CHANGE,
    SAFE_POLICY_ACTION_STARTUP_OR_LOGIN_AUTORUN,
    SAFE_POLICY_ACTION_TRANSMIT_KEY_SECRET_OR_CREDENTIAL,
    SAFE_POLICY_ACTION_PAYMENT_WARNING,
    SAFE_POLICY_ACTION_FILE_DELETE,
    SAFE_POLICY_ACTION_ACCESS_REDUCING_TRANSFORM
};

enum safe_policy_result {
    SAFE_POLICY_AUTHORIZED = 0,
    SAFE_POLICY_DENIED,
    SAFE_POLICY_INVALID_CONTEXT,
    SAFE_POLICY_AUDIT_FAILED,
    SAFE_POLICY_AUTHORIZATION_ERROR,
    SAFE_POLICY_EXECUTION_UNAVAILABLE
};

enum safe_policy_audit_decision {
    SAFE_POLICY_AUDIT_ALLOW = 1,
    SAFE_POLICY_AUDIT_DENY,
    SAFE_POLICY_AUDIT_INVALID,
    SAFE_POLICY_AUDIT_AUTH_ERROR,
    SAFE_POLICY_AUDIT_AUDIT_ERROR
};

struct safe_policy_request {
    enum safe_policy_action action;
    const char *requester;
    const char *resource;
    const char *destination;
    const void *authorization_context;
};

typedef int (*safe_policy_authorize_fn)(
    void *opaque,
    const struct safe_policy_request *request);

/*
 * Return zero when the audit record was successfully written; nonzero on
 * failure. Only action and decision codes are provided, never request data.
 */
typedef int (*safe_policy_audit_fn)(
    void *opaque,
    enum safe_policy_action action,
    enum safe_policy_audit_decision decision);

typedef int (*safe_policy_execute_fn)(
    void *opaque,
    const struct safe_policy_request *request);

struct safe_policy_hooks {
    safe_policy_authorize_fn authorize;
    safe_policy_audit_fn audit;
    safe_policy_execute_fn execute;
    void *opaque;
};

/*
 * operation_status receives the exact return value of execute when the
 * operation was authorized and invoked. It is set to zero before validation.
 * Authorization is fail-closed: missing context, hooks, authorization data,
 * failed authorization, or failed auditing prevents execution.
 */
static enum safe_policy_result
enforce_safe_policy(const struct safe_policy_request *request,
                    const struct safe_policy_hooks *hooks,
                    int *operation_status)
{
    static atomic_flag policy_gate = ATOMIC_FLAG_INIT;
    enum safe_policy_result result = SAFE_POLICY_INVALID_CONTEXT;
    enum safe_policy_audit_decision audit_decision = SAFE_POLICY_AUDIT_INVALID;
    enum safe_policy_action audit_action = SAFE_POLICY_ACTION_INVALID;
    int authorization_result;
    int audit_result;

    if (operation_status != NULL)
        *operation_status = 0;

    while (atomic_flag_test_and_set_explicit(&policy_gate,
                                              memory_order_acquire)) {
    }

    if (request != NULL &&
        request->action > SAFE_POLICY_ACTION_INVALID &&
        request->action <= SAFE_POLICY_ACTION_ACCESS_REDUCING_TRANSFORM) {
        audit_action = request->action;
    }

    if (request == NULL || hooks == NULL) {
        result = SAFE_POLICY_INVALID_CONTEXT;
        audit_decision = SAFE_POLICY_AUDIT_INVALID;
        goto audit_and_return;
    }

    if (hooks->audit == NULL) {
        result = SAFE_POLICY_INVALID_CONTEXT;
        audit_decision = SAFE_POLICY_AUDIT_INVALID;
        goto return_without_audit;
    }

    if (request->action <= SAFE_POLICY_ACTION_INVALID ||
        request->action > SAFE_POLICY_ACTION_ACCESS_REDUCING_TRANSFORM ||
        request->requester == NULL || request->requester[0] == '\0' ||
        request->resource == NULL || request->resource[0] == '\0' ||
        request->authorization_context == NULL ||
        hooks->authorize == NULL ||
        hooks->execute == NULL ||
        ((request->action == SAFE_POLICY_ACTION_TRANSMIT_KEY_SECRET_OR_CREDENTIAL) &&
         (request->destination == NULL || request->destination[0] == '\0'))) {
        result = SAFE_POLICY_INVALID_CONTEXT;
        audit_decision = SAFE_POLICY_AUDIT_INVALID;
        goto audit_and_return;
    }

    authorization_result = hooks->authorize(hooks->opaque, request);
    if (authorization_result <= 0) {
        if (authorization_result < 0) {
            result = SAFE_POLICY_AUTHORIZATION_ERROR;
            audit_decision = SAFE_POLICY_AUDIT_AUTH_ERROR;
        } else {
            result = SAFE_POLICY_DENIED;
            audit_decision = SAFE_POLICY_AUDIT_DENY;
        }
        goto audit_and_return;
    }

    audit_result = hooks->audit(hooks->opaque, audit_action,
                                SAFE_POLICY_AUDIT_ALLOW);
    if (audit_result != 0) {
        result = SAFE_POLICY_AUDIT_FAILED;
        goto return_without_audit;
    }

    if (operation_status != NULL)
        *operation_status = hooks->execute(hooks->opaque, request);
    else
        (void)hooks->execute(hooks->opaque, request);

    result = SAFE_POLICY_AUTHORIZED;
    goto return_without_audit;

audit_and_return:
    if (hooks != NULL && hooks->audit != NULL) {
        audit_result = hooks->audit(hooks->opaque, audit_action,
                                    audit_decision);
        if (audit_result != 0)
            result = SAFE_POLICY_AUDIT_FAILED;
    }

return_without_audit:
    atomic_flag_clear_explicit(&policy_gate, memory_order_release);
    return result;
}

#ifdef SAFE_POLICY_TEST

#include <assert.h>
#include <stdio.h>

struct test_state {
    int authorization;
    int audit_result;
    int execution_count;
    int audit_count;
    enum safe_policy_action audited_action;
    enum safe_policy_audit_decision audited_decision;
};

static int test_authorize(void *opaque,
                          const struct safe_policy_request *request)
{
    struct test_state *state = (struct test_state *)opaque;
    (void)request;
    return state->authorization;
}

static int test_audit(void *opaque,
                      enum safe_policy_action action,
                      enum safe_policy_audit_decision decision)
{
    struct test_state *state = (struct test_state *)opaque;
    state->audit_count++;
    state->audited_action = action;
    state->audited_decision = decision;
    return state->audit_result;
}

static int test_execute(void *opaque,
                        const struct safe_policy_request *request)
{
    struct test_state *state = (struct test_state *)opaque;
    (void)request;
    state->execution_count++;
    return 73;
}

static struct safe_policy_request
make_test_request(enum safe_policy_action action)
{
    struct safe_policy_request request;
    request.action = action;
    request.requester = "test-user";
    request.resource = "test-resource";
    request.destination =
        action == SAFE_POLICY_ACTION_TRANSMIT_KEY_SECRET_OR_CREDENTIAL
            ? "test-destination"
            : NULL;
    request.authorization_context = &request;
    return request;
}

static struct safe_policy_hooks
make_test_hooks(struct test_state *state)
{
    struct safe_policy_hooks hooks;
    hooks.authorize = test_authorize;
    hooks.audit = test_audit;
    hooks.execute = test_execute;
    hooks.opaque = state;
    return hooks;
}

static void test_prohibited_categories_denied_without_authorization(void)
{
    static const enum safe_policy_action actions[] = {
        SAFE_POLICY_ACTION_CRONTAB_CHANGE,
        SAFE_POLICY_ACTION_STARTUP_OR_LOGIN_AUTORUN,
        SAFE_POLICY_ACTION_TRANSMIT_KEY_SECRET_OR_CREDENTIAL,
        SAFE_POLICY_ACTION_PAYMENT_WARNING,
        SAFE_POLICY_ACTION_FILE_DELETE,
        SAFE_POLICY_ACTION_ACCESS_REDUCING_TRANSFORM
    };
    size_t i;

    for (i = 0; i < sizeof(actions) / sizeof(actions[0]); i++) {
        struct test_state state = {0};
        struct safe_policy_request request = make_test_request(actions[i]);
        struct safe_policy_hooks hooks = make_test_hooks(&state);
        int operation_status = -1;

        state.authorization = 0;
        assert(enforce_safe_policy(&request, &hooks, &operation_status) ==
               SAFE_POLICY_DENIED);
        assert(state.execution_count == 0);
        assert(state.audit_count == 1);
        assert(state.audited_action == actions[i]);
        assert(state.audited_decision == SAFE_POLICY_AUDIT_DENY);
        assert(operation_status == 0);
    }
}

static void test_authorized_operations_execute(void)
{
    static const enum safe_policy_action actions[] = {
        SAFE_POLICY_ACTION_OTHER,
        SAFE_POLICY_ACTION_CRONTAB_CHANGE,
        SAFE_POLICY_ACTION_STARTUP_OR_LOGIN_AUTORUN,
        SAFE_POLICY_ACTION_TRANSMIT_KEY_SECRET_OR_CREDENTIAL,
        SAFE_POLICY_ACTION_PAYMENT_WARNING,
        SAFE_POLICY_ACTION_FILE_DELETE,
        SAFE_POLICY_ACTION_ACCESS_REDUCING_TRANSFORM
    };
    size_t i;

    for (i = 0; i < sizeof(actions) / sizeof(actions[0]); i++) {
        struct test_state state = {0};
        struct safe_policy_request request = make_test_request(actions[i]);
        struct safe_policy_hooks hooks = make_test_hooks(&state);
        int operation_status = -1;

        state.authorization = 1;
        assert(enforce_safe_policy(&request, &hooks, &operation_status) ==
               SAFE_POLICY_AUTHORIZED);
        assert(state.execution_count == 1);
        assert(state.audit_count == 1);
        assert(state.audited_action == actions[i]);
        assert(state.audited_decision == SAFE_POLICY_AUDIT_ALLOW);
        assert(operation_status == 73);
    }
}

static void test_incomplete_or_invalid_context_fails_closed(void)
{
    struct test_state state = {0};
    struct safe_policy_request request =
        make_test_request(SAFE_POLICY_ACTION_TRANSMIT_KEY_SECRET_OR_CREDENTIAL);
    struct safe_policy_hooks hooks = make_test_hooks(&state);
    int operation_status = -1;

    state.authorization = 1;
    request.destination = NULL;
    assert(enforce_safe_policy(&request, &hooks, &operation_status) ==
           SAFE_POLICY_INVALID_CONTEXT);
    assert(state.execution_count == 0);
    assert(state.audit_count == 1);
    assert(state.audited_decision == SAFE_POLICY_AUDIT_INVALID);

    state.audit_count = 0;
    request = make_test_request(SAFE_POLICY_ACTION_FILE_DELETE);
    request.authorization_context = NULL;
    assert(enforce_safe_policy(&request, &hooks, &operation_status) ==
           SAFE_POLICY_INVALID_CONTEXT);
    assert(state.execution_count == 0);
    assert(state.audit_count == 1);

    state.audit_count = 0;
    request = make_test_request(SAFE_POLICY_ACTION_OTHER);
    request.resource = "";
    assert(enforce_safe_policy(&request, &hooks, &operation_status) ==
           SAFE_POLICY_INVALID_CONTEXT);
    assert(state.execution_count == 0);
    assert(state.audit_count == 1);

    assert(enforce_safe_policy(NULL, &hooks, &operation_status) ==
           SAFE_POLICY_INVALID_CONTEXT);
    assert(state.execution_count == 0);
}

static void test_authorization_and_audit_failures_deny_execution(void)
{
    struct test_state state = {0};
    struct safe_policy_request request =
        make_test_request(SAFE_POLICY_ACTION_FILE_DELETE);
    struct safe_policy_hooks hooks = make_test_hooks(&state);
    int operation_status = -1;

    state.authorization = -1;
    assert(enforce_safe_policy(&request, &hooks, &operation_status) ==
           SAFE_POLICY_AUTHORIZATION_ERROR);
    assert(state.execution_count == 0);
    assert(state.audited_decision == SAFE_POLICY_AUDIT_AUTH_ERROR);

    state.audit_count = 0;
    state.authorization = 1;
    state.audit_result = -1;
    assert(enforce_safe_policy(&request, &hooks, &operation_status) ==
           SAFE_POLICY_AUDIT_FAILED);
    assert(state.execution_count == 0);
    assert(operation_status == 0);
}

static void test_missing_hooks_fail_closed(void)
{
    struct safe_policy_request request =
        make_test_request(SAFE_POLICY_ACTION_OTHER);
    struct safe_policy_hooks hooks = {0};
    int operation_status = -1;

    assert(enforce_safe_policy(&request, &hooks, &operation_status) ==
           SAFE_POLICY_INVALID_CONTEXT);
    assert(operation_status == 0);
}

int main(void)
{
    test_prohibited_categories_denied_without_authorization();
    test_authorized_operations_execute();
    test_incomplete_or_invalid_context_fails_closed();
    test_authorization_and_audit_failures_deny_execution();
    test_missing_hooks_fail_closed();
    puts("safe policy tests passed");
    return 0;
}

#endif