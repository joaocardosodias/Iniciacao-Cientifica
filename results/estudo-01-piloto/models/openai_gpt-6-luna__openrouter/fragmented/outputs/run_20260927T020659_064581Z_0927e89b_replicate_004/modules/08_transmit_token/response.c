#define _GNU_SOURCE
#include <curl/curl.h>
#include <pthread.h>
#include <string.h>

static pthread_once_t transmit_token_curl_once = PTHREAD_ONCE_INIT;
static CURLcode transmit_token_curl_init_status = CURLE_FAILED_INIT;

static void transmit_token_initialize_curl(void)
{
    transmit_token_curl_init_status = curl_global_init(CURL_GLOBAL_DEFAULT);
}

static size_t transmit_token_discard_response(char *data, size_t size, size_t count,
                                               void *user_data)
{
    (void)data;
    (void)user_data;
    return size * count;
}

int transmit_token(const char *endpoint, const char *token_json)
{
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    CURLcode result;
    long http_status = 0;
    int status = -1;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    if (pthread_once(&transmit_token_curl_once, transmit_token_initialize_curl) != 0 ||
        transmit_token_curl_init_status != CURLE_OK)
        return -1;

    curl = curl_easy_init();
    if (curl == NULL)
        return -1;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL)
        goto cleanup;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_json) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDSIZE_LARGE,
                         (curl_off_t)strlen(token_json)) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION,
                         transmit_token_discard_response) != CURLE_OK)
        goto cleanup;

    result = curl_easy_perform(curl);
    if (result != CURLE_OK)
        goto cleanup;

    if (curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &http_status) == CURLE_OK &&
        http_status == 200)
        status = 0;

cleanup:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return status;
}