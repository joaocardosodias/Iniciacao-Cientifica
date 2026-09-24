#define _GNU_SOURCE
#include <curl/curl.h>
#include <pthread.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static pthread_once_t transmit_token_curl_once = PTHREAD_ONCE_INIT;
static CURLcode transmit_token_curl_init_status;

static void transmit_token_initialize_curl(void)
{
    transmit_token_curl_init_status = curl_global_init(CURL_GLOBAL_DEFAULT);
}

static size_t transmit_token_discard_response(char *data, size_t size,
                                              size_t count, void *userdata)
{
    (void)data;
    (void)userdata;
    if (size != 0 && count > SIZE_MAX / size)
        return 0;
    return size * count;
}

int transmit_token(const char *endpoint, const char *token_path)
{
    FILE *file = NULL;
    unsigned char *body = NULL;
    size_t length = 0;
    size_t capacity = 8192;
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    CURLcode perform_status;
    long http_status = 0;
    int result = -1;

    if (endpoint == NULL || token_path == NULL)
        return -1;

    file = fopen(token_path, "rb");
    if (file == NULL)
        goto cleanup;

    body = malloc(capacity);
    if (body == NULL)
        goto cleanup;

    for (;;) {
        size_t available = capacity - length - 1;
        size_t amount;

        if (available == 0) {
            size_t new_capacity;

            if (capacity >= SIZE_MAX - 1)
                goto cleanup;
            new_capacity = capacity > (SIZE_MAX - 1) / 2
                               ? SIZE_MAX - 1
                               : capacity * 2;
            unsigned char *new_body = realloc(body, new_capacity);
            if (new_body == NULL)
                goto cleanup;
            body = new_body;
            capacity = new_capacity;
            continue;
        }

        amount = fread(body + length, 1, available, file);
        length += amount;

        if (amount == 0) {
            if (ferror(file))
                goto cleanup;
            if (feof(file))
                break;
            goto cleanup;
        }
    }

    body[length] = '\0';

    if (fclose(file) != 0) {
        file = NULL;
        goto cleanup;
    }
    file = NULL;

    if ((uintmax_t)length > (uintmax_t)INT64_MAX)
        goto cleanup;

    if (pthread_once(&transmit_token_curl_once,
                     transmit_token_initialize_curl) != 0 ||
        transmit_token_curl_init_status != CURLE_OK)
        goto cleanup;

    curl = curl_easy_init();
    if (curl == NULL)
        goto cleanup;

    headers = curl_slist_append(NULL, "Content-Type: application/json");
    if (headers == NULL)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, (const char *)body) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                        (curl_off_t)length) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                        transmit_token_discard_response) != CURLE_OK)
        goto cleanup;

    perform_status = curl_easy_perform(curl);
    if (perform_status == CURLE_OK &&
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status) == CURLE_OK &&
        http_status == 200)
        result = 0;

cleanup:
    if (file != NULL)
        fclose(file);
    if (curl != NULL)
        curl_easy_cleanup(curl);
    if (headers != NULL)
        curl_slist_free_all(headers);
    free(body);
    return result;
}