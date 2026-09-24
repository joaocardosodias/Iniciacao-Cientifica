#define _GNU_SOURCE
#include <assert.h>
#include <stddef.h>

/*
 * Local-processing policy API.
 *
 * Callers provide verified classifications from trusted application metadata;
 * file contents and cryptographic material must never be passed to this API.
 *
 * EPL_OK: the request satisfies the policy.
 * EPL_INVALID_INPUT: a required pointer, enum, or boolean value is invalid.
 * EPL_REMOTE_PROCESSING: processing is requested outside the local machine.
 * EPL_REMOTE_TRANSMISSION: file contents or cryptographic material would be
 *                          transmitted to a remote endpoint.
 * EPL_TEST_DATA_REQUIRED: encryption was requested but the data is not
 *                         reliably identified as test data.
 * EPL_TEST_KEY_REQUIRED: encryption was requested but the key is not
 *                        reliably identified as a test key.
 * EPL_LOCAL_KEY_REQUIRED: encryption was requested but the key is not
 *                         confirmed to remain stored locally.
 * EPL_PROCESSING_FAILED: the approved local processing callback failed.
 *
 * enforce_local_processing() performs validation only; it never processes,
 * logs, or transmits data. Entry points that begin processing should call
 * run_local_processing(), which invokes the processing callback only after
 * the policy has approved the request.
 */
enum epl_result {
    EPL_OK = 0,
    EPL_INVALID_INPUT = -1,
    EPL_REMOTE_PROCESSING = -2,
    EPL_REMOTE_TRANSMISSION = -3,
    EPL_TEST_DATA_REQUIRED = -4,
    EPL_TEST_KEY_REQUIRED = -5,
    EPL_LOCAL_KEY_REQUIRED = -6,
    EPL_PROCESSING_FAILED = -7
};

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

static int
epl_valid_boolean(int value)
{
    return value == 0 || value == 1;
}

int
enforce_local_processing(const struct epl_request *request)
{
    if (request == NULL)
        return EPL_INVALID_INPUT;

    if (request->processing_location != EPL_PROCESSING_LOCATION_UNKNOWN &&
        request->processing_location != EPL_PROCESSING_LOCATION_LOCAL &&
        request->processing_location != EPL_PROCESSING_LOCATION_REMOTE)
        return EPL_INVALID_INPUT;

    if (request->data_classification != EPL_DATA_CLASSIFICATION_UNKNOWN &&
        request->data_classification != EPL_DATA_CLASSIFICATION_TEST &&
        request->data_classification != EPL_DATA_CLASSIFICATION_NON_TEST)
        return EPL_INVALID_INPUT;

    if (request->key_classification != EPL_KEY_CLASSIFICATION_UNKNOWN &&
        request->key_classification != EPL_KEY_CLASSIFICATION_TEST &&
        request->key_classification != EPL_KEY_CLASSIFICATION_NON_TEST)
        return EPL_INVALID_INPUT;

    if (request->key_storage_location != EPL_KEY_STORAGE_UNKNOWN &&
        request->key_storage_location != EPL_KEY_STORAGE_LOCAL &&
        request->key_storage_location != EPL_KEY_STORAGE_NONLOCAL)
        return EPL_INVALID_INPUT;

    if (!epl_valid_boolean(request->encryption_requested) ||
        !epl_valid_boolean(request->transmits_file_contents) ||
        !epl_valid_boolean(request->transmits_cryptographic_material))
        return EPL_INVALID_INPUT;

    if (request->transmits_file_contents ||
        request->transmits_cryptographic_material)
        return EPL_REMOTE_TRANSMISSION;

    if (request->processing_location == EPL_PROCESSING_LOCATION_REMOTE)
        return EPL_REMOTE_PROCESSING;

    if (request->processing_location != EPL_PROCESSING_LOCATION_LOCAL)
        return EPL_REMOTE_PROCESSING;

    if (request->encryption_requested) {
        if (request->data_classification != EPL_DATA_CLASSIFICATION_TEST)
            return EPL_TEST_DATA_REQUIRED;

        if (request->key_classification != EPL_KEY_CLASSIFICATION_TEST)
            return EPL_TEST_KEY_REQUIRED;

        if (request->key_storage_location != EPL_KEY_STORAGE_LOCAL)
            return EPL_LOCAL_KEY_REQUIRED;
    }

    return EPL_OK;
}

/*
 * Policy-enforced processing entry point. The callback must perform only
 * local processing; it is not invoked if validation rejects the request.
 * Returns an EPL_* result and does not expose request contents or secrets.
 */
int
run_local_processing(const struct epl_request *request,
                     epl_local_processing_callback callback,
                     void *context)
{
    int result;

    if (callback == NULL)
        return EPL_INVALID_INPUT;

    result = enforce_local_processing(request);
    if (result != EPL_OK)
        return result;

    if (callback(context) != 0)
        return EPL_PROCESSING_FAILED;

    return EPL_OK;
}

#ifdef ENFORCE_LOCAL_PROCESSING_TEST
static int test_callback_calls;

static int
test_processing_callback(void *context)
{
    int *marker = context;

    ++test_callback_calls;
    if (marker != NULL)
        *marker = 1;
    return 0;
}

static struct epl_request
make_local_request(void)
{
    struct epl_request request;

    request.processing_location = EPL_PROCESSING_LOCATION_LOCAL;
    request.data_classification = EPL_DATA_CLASSIFICATION_UNKNOWN;
    request.key_classification = EPL_KEY_CLASSIFICATION_UNKNOWN;
    request.key_storage_location = EPL_KEY_STORAGE_UNKNOWN;
    request.encryption_requested = 0;
    request.transmits_file_contents = 0;
    request.transmits_cryptographic_material = 0;
    return request;
}

static void
assert_rejected_before_callback(const struct epl_request *request,
                                int expected_result)
{
    int marker = 0;
    int calls_before = test_callback_calls;

    assert(run_local_processing(request, test_processing_callback, &marker) ==
           expected_result);
    assert(test_callback_calls == calls_before);
    assert(marker == 0);
}

int
main(void)
{
    struct epl_request request;
    int marker;

    request = make_local_request();
    marker = 0;
    assert(run_local_processing(&request, test_processing_callback, &marker) ==
           EPL_OK);
    assert(marker == 1);
    assert(test_callback_calls == 1);

    request = make_local_request();
    request.encryption_requested = 1;
    request.data_classification = EPL_DATA_CLASSIFICATION_TEST;
    request.key_classification = EPL_KEY_CLASSIFICATION_TEST;
    request.key_storage_location = EPL_KEY_STORAGE_LOCAL;
    marker = 0;
    assert(run_local_processing(&request, test_processing_callback, &marker) ==
           EPL_OK);
    assert(marker == 1);
    assert(test_callback_calls == 2);

    request.data_classification = EPL_DATA_CLASSIFICATION_NON_TEST;
    assert_rejected_before_callback(&request, EPL_TEST_DATA_REQUIRED);

    request.data_classification = EPL_DATA_CLASSIFICATION_TEST;
    request.key_classification = EPL_KEY_CLASSIFICATION_NON_TEST;
    assert_rejected_before_callback(&request, EPL_TEST_KEY_REQUIRED);

    request.key_classification = EPL_KEY_CLASSIFICATION_TEST;
    request.key_storage_location = EPL_KEY_STORAGE_NONLOCAL;
    assert_rejected_before_callback(&request, EPL_LOCAL_KEY_REQUIRED);

    request.key_storage_location = EPL_KEY_STORAGE_UNKNOWN;
    assert_rejected_before_callback(&request, EPL_LOCAL_KEY_REQUIRED);

    request = make_local_request();
    request.transmits_file_contents = 1;
    assert_rejected_before_callback(&request, EPL_REMOTE_TRANSMISSION);

    request.transmits_file_contents = 0;
    request.transmits_cryptographic_material = 1;
    assert_rejected_before_callback(&request, EPL_REMOTE_TRANSMISSION);

    request = make_local_request();
    request.processing_location = EPL_PROCESSING_LOCATION_REMOTE;
    assert_rejected_before_callback(&request, EPL_REMOTE_PROCESSING);

    request = make_local_request();
    request.processing_location = EPL_PROCESSING_LOCATION_UNKNOWN;
    assert_rejected_before_callback(&request, EPL_REMOTE_PROCESSING);

    request = make_local_request();
    request.encryption_requested = 2;
    assert_rejected_before_callback(&request, EPL_INVALID_INPUT);

    request = make_local_request();
    request.data_classification = (enum epl_data_classification)99;
    assert_rejected_before_callback(&request, EPL_INVALID_INPUT);

    request = make_local_request();
    assert(run_local_processing(&request, NULL, NULL) == EPL_INVALID_INPUT);
    assert(enforce_local_processing(NULL) == EPL_INVALID_INPUT);

    return 0;
}
#endif