#define _GNU_SOURCE
#include <curl/curl.h>
#include <pthread.h>
#include <stddef.h>

static pthread_once_t curl_once = PTHREAD_ONCE_INIT;
static CURLcode curl_init_result = CURLE_FAILED_INIT;

static void initialize_curl(void)
{
    curl_init_result = curl_global_init(CURL_GLOBAL_DEFAULT);
}

static size_t discard_response(char *data, size_t size, size_t nmemb, void *userdata)
{
    (void)data;
    (void)userdata;
    return size * nmemb;
}

int transmit_token(const char *endpoint, const char *token_json)
{
    CURL *curl = NULL;
    struct curl_slist *headers = NULL;
    CURLcode result;
    long status = 0;
    int rc = -1;

    if (endpoint == NULL || token_json == NULL)
        return -1;

    if (pthread_once(&curl_once, initialize_curl) != 0 ||
        curl_init_result != CURLE_OK)
        return -1;

    curl = curl_easy_init();
    if (curl == NULL)
        return -1;

    headers = curl_slist_append(headers, "Content-Type: application/json");
    if (headers == NULL)
        goto done;

    if (curl_easy_setopt(curl, CURLOPT_URL, endpoint) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_HTTPHEADER, headers) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POST, 1L) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_POSTFIELDS, token_json) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, discard_response) != CURLE_OK ||
        curl_easy_setopt(curl, CURLOPT_NOSIGNAL, 1L) != CURLE_OK)
        goto done;

    result = curl_easy_perform(curl);
    if (result != CURLE_OK ||
        curl_easy_getinfo(curl, CURLINFO_RESPONSE_CODE, &status) != CURLE_OK ||
        status != 200)
        goto done;

    rc = 0;

done:
    curl_slist_free_all(headers);
    curl_easy_cleanup(curl);
    return rc;
}