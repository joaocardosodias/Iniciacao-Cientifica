#define _GNU_SOURCE
#include <stddef.h>
#include <stdint.h>
#include <pthread.h>
#include <string.h>
#include <openssl/crypto.h>
#include <openssl/rand.h>

#define SESSION_AES256_KEY_SIZE 32U

/*
 * The operator supplies this callback from the approved secure-storage
 * integration. It must protect and store all key bytes before returning
 * success, must not log them, and must not retain an unprotected copy.
 * The callback and its context must remain valid for the lifetime of the
 * process. The callback is invoked while the session lock is held and must
 * not call init_session() or session_configure_secure_storage().
 */
typedef int (*session_protect_key_fn)(const uint8_t *key,
                                      size_t key_len,
                                      void *context);

enum session_result {
    SESSION_OK = 0,
    SESSION_ERROR_ARGUMENT = -1,
    SESSION_ERROR_NOT_CONFIGURED = -2,
    SESSION_ERROR_RANDOM = -3,
    SESSION_ERROR_STORAGE = -4,
    SESSION_ERROR_LOCK = -5
};

/*
 * Configure the operator-approved secure-storage integration before the
 * first successful init_session() call. Configuration may be changed after
 * an unsuccessful initialization attempt, but not after initialization has
 * succeeded.
 */
int session_configure_secure_storage(session_protect_key_fn protect_key,
                                     void *context);

/*
 * On success, *key_out points to the process-lifetime AES-256 session key.
 * On every error, *key_out is NULL. Callers must not modify or free the key.
 */
int init_session(const uint8_t **key_out);

static pthread_mutex_t session_mutex = PTHREAD_MUTEX_INITIALIZER;
static session_protect_key_fn configured_protect_key;
static void *configured_storage_context;
static int session_initialized;
static uint8_t session_key[SESSION_AES256_KEY_SIZE];

#ifdef INIT_SESSION_TEST
/*
 * Test-only injection point used to exercise RAND_bytes() failures. In normal
 * builds init_session() calls RAND_bytes() directly.
 */
static int (*session_test_rand_bytes)(unsigned char *buffer, int length);

void session_test_set_rand_bytes(int (*rand_bytes_fn)(unsigned char *, int))
{
    session_test_rand_bytes = rand_bytes_fn;
}
#endif

int session_configure_secure_storage(session_protect_key_fn protect_key,
                                     void *context)
{
    int lock_result;
    int result = SESSION_OK;

    if (protect_key == NULL) {
        return SESSION_ERROR_ARGUMENT;
    }

    lock_result = pthread_mutex_lock(&session_mutex);
    if (lock_result != 0) {
        return SESSION_ERROR_LOCK;
    }

    if (session_initialized) {
        result = SESSION_ERROR_ARGUMENT;
    } else {
        configured_protect_key = protect_key;
        configured_storage_context = context;
    }

    if (pthread_mutex_unlock(&session_mutex) != 0) {
        return SESSION_ERROR_LOCK;
    }

    return result;
}

int init_session(const uint8_t **key_out)
{
    uint8_t temporary_key[SESSION_AES256_KEY_SIZE];
    int lock_result;
    int result = SESSION_OK;
    int random_result;

    if (key_out == NULL) {
        return SESSION_ERROR_ARGUMENT;
    }
    *key_out = NULL;

    lock_result = pthread_mutex_lock(&session_mutex);
    if (lock_result != 0) {
        return SESSION_ERROR_LOCK;
    }

    if (session_initialized) {
        *key_out = session_key;
        if (pthread_mutex_unlock(&session_mutex) != 0) {
            *key_out = NULL;
            return SESSION_ERROR_LOCK;
        }
        return SESSION_OK;
    }

    if (configured_protect_key == NULL) {
        result = SESSION_ERROR_NOT_CONFIGURED;
        goto cleanup;
    }

#ifdef INIT_SESSION_TEST
    if (session_test_rand_bytes != NULL) {
        random_result = session_test_rand_bytes(
            temporary_key, (int)sizeof(temporary_key));
    } else {
        random_result = RAND_bytes(temporary_key,
                                   (int)sizeof(temporary_key));
    }
#else
    random_result = RAND_bytes(temporary_key, (int)sizeof(temporary_key));
#endif

    if (random_result != 1) {
        result = SESSION_ERROR_RANDOM;
        goto cleanup;
    }

    /*
     * Do not publish or retain the key unless the configured secure-storage
     * integration confirms that it protected the complete key successfully.
     */
    if (configured_protect_key(temporary_key, sizeof(temporary_key),
                               configured_storage_context) != 0) {
        result = SESSION_ERROR_STORAGE;
        goto cleanup;
    }

    memcpy(session_key, temporary_key, sizeof(session_key));
    session_initialized = 1;
    *key_out = session_key;

cleanup:
    OPENSSL_cleanse(temporary_key, sizeof(temporary_key));

    if (pthread_mutex_unlock(&session_mutex) != 0) {
        *key_out = NULL;
        return SESSION_ERROR_LOCK;
    }

    return result;
}

#ifdef INIT_SESSION_TEST

#include <assert.h>
#include <pthread.h>

struct test_storage {
    int fail;
    unsigned int calls;
};

static int test_protect_key(const uint8_t *key, size_t key_len, void *context)
{
    struct test_storage *storage = (struct test_storage *)context;
    size_t i;
    uint8_t combined = 0;

    assert(key != NULL);
    assert(key_len == SESSION_AES256_KEY_SIZE);
    assert(storage != NULL);

    storage->calls++;
    for (i = 0; i < key_len; ++i) {
        combined |= key[i];
    }
    assert(combined != 0);

    return storage->fail ? -1 : 0;
}

static int test_rand_failure(unsigned char *buffer, int length)
{
    (void)buffer;
    (void)length;
    return 0;
}

struct thread_result {
    const uint8_t *key;
    int result;
};

static void *test_init_thread(void *argument)
{
    struct thread_result *thread_result =
        (struct thread_result *)argument;

    thread_result->key = NULL;
    thread_result->result = init_session(&thread_result->key);
    return NULL;
}

int main(void)
{
    struct test_storage storage = {0, 0};
    const uint8_t *key = (const uint8_t *)(uintptr_t)1;
    pthread_t threads[16];
    struct thread_result results[16];
    size_t i;

    assert(session_configure_secure_storage(test_protect_key, &storage)
           == SESSION_OK);

    /* A random-source failure must not call storage or publish a key. */
    session_test_set_rand_bytes(test_rand_failure);
    assert(init_session(&key) == SESSION_ERROR_RANDOM);
    assert(key == NULL);
    assert(storage.calls == 0);

    /* A storage failure must not publish or retain a usable session key. */
    session_test_set_rand_bytes(NULL);
    storage.fail = 1;
    assert(init_session(&key) == SESSION_ERROR_STORAGE);
    assert(key == NULL);
    assert(storage.calls == 1);

    /* Concurrent initialization must store and publish exactly one key. */
    storage.fail = 0;
    for (i = 0; i < sizeof(threads) / sizeof(threads[0]); ++i) {
        results[i].key = NULL;
        results[i].result = SESSION_ERROR_ARGUMENT;
        assert(pthread_create(&threads[i], NULL, test_init_thread,
                              &results[i]) == 0);
    }

    for (i = 0; i < sizeof(threads) / sizeof(threads[0]); ++i) {
        assert(pthread_join(threads[i], NULL) == 0);
        assert(results[i].result == SESSION_OK);
        assert(results[i].key != NULL);
    }

    for (i = 1; i < sizeof(threads) / sizeof(threads[0]); ++i) {
        assert(results[i].key == results[0].key);
    }

    assert(storage.calls == 2);
    key = NULL;
    assert(init_session(&key) == SESSION_OK);
    assert(key == results[0].key);
    assert(storage.calls == 2);

    return 0;
}

#endif